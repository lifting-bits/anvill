#include <sstream>
#include <string>
#include <iostream>
#include <algorithm>
#include <bitset>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Metadata.h>

#include <remill/BC/Util.h>
#include <remill/Arch/Arch.h>

#include <anvill/Decl.h>

#include "json.hpp"

struct RegisterConstraint;

// forward declarations for now TODO: change this
remill::Register* tryRegisterAllocate(const llvm::Argument& argument, std::vector<bool>& reserved, const std::vector<RegisterConstraint>& register_constraints);
std::string translateType(const llvm::Type& type);

// for convenience
using json = nlohmann::json;

DECLARE_string(arch);
DECLARE_string(os);
DEFINE_string(bc_file, "", "Path to BITcode file containing data to be specified");

namespace remill {
	class Arch;
	class IntrinsicTable;
	struct Register;
}

enum SizeConstraint {
	BIT8 = (1 << 0),
	BIT16 = (1 << 1),
	BIT32 = (1 << 2),
	BIT64 = (1 << 3),
	BIT128 = (1 << 4),

	MAXBIT128 = BIT128 | BIT64 | BIT32 | BIT16 | BIT8,
	MAXBIT64 = BIT64 | BIT32 | BIT16 | BIT8,
	MAXBIT32 = BIT32 | BIT16 | BIT8,
};


enum TypeConstraint {
	TYPEINT = (1 << 0),
	TYPEPTR = (1 << 1),
	TYPEFLOAT = (1 << 2),
	TYPEVEC = (1 << 3),

	TYPEINTEGRAL = TYPEINT | TYPEPTR,
};


struct RegisterConstraint {
	RegisterConstraint(std::string _register_name, TypeConstraint _type_constraint, SizeConstraint _size_constraint) 
	  : register_name(_register_name), type_constraint(_type_constraint), size_constraint(_size_constraint) {}
	
	std::string register_name;
	TypeConstraint type_constraint;
	SizeConstraint size_constraint;
};

struct ParameterPasses {};
struct ReturnPasses {};

class CallingConvention {
public:
	CallingConvention(llvm::CallingConv::ID _identity) : identity(_identity){}
	virtual ~CallingConvention() {}

	virtual std::vector<anvill::ParameterDecl> bindParameters(const llvm::Function& function) = 0;
	virtual std::vector<anvill::ValueDecl> bindReturnValues(const llvm::Function& function) = 0;

	llvm::CallingConv::ID getIdentity() { return identity; }

private:
	llvm::CallingConv::ID identity;
};


class X86_64_SysV : public CallingConvention {
public:
	X86_64_SysV() :CallingConvention(llvm::CallingConv::X86_64_SysV) {}
	~X86_64_SysV() {}
	
	std::vector<anvill::ParameterDecl> bindParameters(const llvm::Function& function) {
		std::vector<anvill::ParameterDecl> parameter_declarations;

		// Create a map of names to parameters
		std::map<unsigned int, std::string> param_names;
		for (auto& block : function) {
			for (auto& inst : block) {
				if (auto debug_inst = llvm::dyn_cast<llvm::DbgInfoIntrinsic>(&inst)) {
					if (auto value_intrin = llvm::dyn_cast<llvm::DbgDeclareInst>(&inst)) {
						const llvm::MDNode* mdn = value_intrin->getVariable();
						const llvm::DILocalVariable* div = llvm::cast<llvm::DILocalVariable>(mdn);

						// Make sure it is actually an argument
						if (div->getArg() != 0) {
							LOG(INFO) << div->getArg() << " : " << div->getName().data();
							param_names[div->getArg()] = div->getName().data();
						}
					}
					else if (auto value_intrin = llvm::dyn_cast<llvm::DbgValueInst>(debug_inst)) {
						const llvm::MDNode* mdn = value_intrin->getVariable();
						const llvm::DILocalVariable* div = llvm::cast<llvm::DILocalVariable>(mdn);

						if (div->getArg() != 0) {
							LOG(INFO) << div->getArg() << " : " << div->getName().data();
							param_names[div->getArg()] = div->getName().data();
						}
					}
				}
			}
		}

		// If we don't have names for some parameters then automatically name them
		unsigned int num_args = (unsigned int) (function.args().end() - function.args().begin());
		for (unsigned int i = 1; i <= num_args; i++) {
			if (!param_names.count(i)) {
				param_names[i] = "param" + std::to_string(i);
			}
		}
		
		// Used to keep track of which registers have been allocated
		std::vector<bool> allocated(register_constraints.size(), false);

		// Stack position of the first argument
		unsigned int stack_offset = 16;

		for (auto& argument : function.args()) {
			anvill::ParameterDecl declaration = {};

			// Try to allocate from a register
			if (remill::Register* reg = tryRegisterAllocate(argument, allocated, register_constraints)) {
				declaration.reg = reg;
			} else {
				// This might be butchering the intended semantics of a register, bu
				remill::Register* mem_reg = new remill::Register("RSP", stack_offset, 8, 0, argument.getType());
				stack_offset += 8;
				declaration.mem_reg = mem_reg;
			}

			// Try to get a name for the IR parameter
			// Need to add 1 because param_names uses logical numbering, but argumetn.getArgNo() uses index numbering
			declaration.name = param_names[argument.getArgNo() + 1];

			parameter_declarations.push_back(declaration);
		}

		return parameter_declarations;
	}

	std::vector<anvill::ValueDecl> bindReturnValues(const llvm::Function& function) {
		std::vector<anvill::ValueDecl> return_value_declarations;

		for (auto& block : function) {
			for (auto& inst : block) {
				if (auto return_inst = llvm::dyn_cast<llvm::ReturnInst>(&inst)) {
					anvill::ValueDecl value_declaration = {};

					const llvm::Value* value = return_inst->getReturnValue();
					value_declaration.type = value->getType();

					// Allocate EAX for now.
					// TODO: what happens if we have more than one return value?
					remill::Register* reg = new remill::Register("RAX", 0, 8, 0, value->getType());
					value_declaration.reg = reg;

					return_value_declarations.push_back(value_declaration);
				}
			}
		}
		
		return return_value_declarations;
	}

private:
	const std::vector<RegisterConstraint> register_constraints = {
		RegisterConstraint("RDI", TYPEINTEGRAL, MAXBIT64),
		RegisterConstraint("RSI", TYPEINTEGRAL, MAXBIT64),
		RegisterConstraint("RDX", TYPEINTEGRAL, MAXBIT64),
		RegisterConstraint("RCX", TYPEINTEGRAL, MAXBIT64),
		RegisterConstraint("R8", TYPEINTEGRAL, MAXBIT64),
		RegisterConstraint("R9", TYPEINTEGRAL, MAXBIT64),

		RegisterConstraint("XMM0", TYPEFLOAT, MAXBIT128),
		RegisterConstraint("XMM1", TYPEFLOAT, MAXBIT128),
		RegisterConstraint("XMM2", TYPEFLOAT, MAXBIT128),
		RegisterConstraint("XMM3", TYPEFLOAT, MAXBIT128),
		RegisterConstraint("XMM4", TYPEFLOAT, MAXBIT128),
		RegisterConstraint("XMM5", TYPEFLOAT, MAXBIT128),
		RegisterConstraint("XMM6", TYPEFLOAT, MAXBIT128),
		RegisterConstraint("XMM7", TYPEFLOAT, MAXBIT128),
	};
};


std::string translateType(const llvm::Type& type) {
	unsigned int id = type.getTypeID();

	std::string ret;
	switch(id) {
		case 0: {
			ret = "void";		
			break;
		}
		case 1: {
			ret = "float16";	
			break;
		}
		case 2: {
			ret = "float32";	
			break;
		}
		case 3: {
			ret = "float64";	
			break;
		}
		
		case 11: {
			ret = "int";
			auto derived = llvm::cast<llvm::IntegerType>(type);
			ret += std::to_string(derived.getBitWidth());
			break;
		}
		case 12: {
			ret = "func";
			break;
		}
		case 13: {
			ret = "struct";
			break;
		}
		case 14: {
			ret = "array";
			break;
		}
		case 15: {
			ret = "ptr";
			auto derived = llvm::dyn_cast<llvm::PointerType>(&type);
			ret += " " + translateType(*derived->getElementType());
			break;
		}

		default:
			LOG(ERROR) << "Could not translate TypeID: " << id;
			break;
	}
	return ret;
} 


// Try to allocate a register for the argument based on the register constraints and what has already been reserved
// Return nullptr if there is not possible register allocation
// I hate returning a naked pointer but thats what remill::Register needs.
// TODO: memory leak?
remill::Register* tryRegisterAllocate(const llvm::Argument& argument, std::vector<bool>& reserved, const std::vector<RegisterConstraint>& register_constraints) {
	llvm::Type& type = *argument.getType();

	SizeConstraint size_constraint;
	TypeConstraint type_constraint;

	if (type.isIntegerTy()) {
		type_constraint = TYPEINT;
		auto derived = llvm::cast<llvm::IntegerType>(type);
		unsigned int width = derived.getBitWidth();
		if (width == 64) {
			size_constraint = BIT64;
		} else {
			// TODO: I know that this is wrong but for now its fine
			size_constraint = MAXBIT32;
		}
	} else if (type.isFloatTy()) {
		type_constraint = TYPEFLOAT;
		// We automatically know it is 32-bit IEEE floating point type
		size_constraint = BIT32;
	} else if (type.isDoubleTy()) {
		type_constraint = TYPEFLOAT;
		// We automatically know it is 64-bit IEEE floating point type
		size_constraint = BIT64;
	}

	for (size_t i = 0; i < register_constraints.size(); i++) {
		const RegisterConstraint& constraint = register_constraints[i];
		if (reserved[i]) {
			continue;
		}
		
		if (size_constraint & constraint.size_constraint && type_constraint & constraint.type_constraint) {
			reserved[i] = true;
			remill::Register* reg = new remill::Register(constraint.register_name, 0, 8, 0, &type);
			return reg;
		}
	}

	return nullptr;
}



// Returns a tuple consisting of arch, os
std::tuple<std::string, std::string>
getPlatformInformation(llvm::Module* module) {
	std::string s = module->getTargetTriple();

	// Split the triple
	replace(s.begin(), s.end(), '-', ' ');
	std::stringstream ss(s);
	std::istream_iterator<std::string> begin(ss);
	std::istream_iterator<std::string> end;
	std::vector<std::string> triple(begin, end);

	// Check that we actually got 3 strings
	if (triple.size() != 3) {
		LOG(ERROR) << "Could not extract a valid triple";
		exit(EXIT_FAILURE);
	}

	std::string arch = triple[0];
	std::string os = triple[2];
	return std::make_tuple(arch, os);
}


// Processes a function
json outputFunction(llvm::Function& func, std::vector<anvill::ParameterDecl> parameter_declarations, std::vector<anvill::ValueDecl> return_value_declarations) {
	json j;
	j["name"] = func.getName().data();

	// This is specific to x86_64 unoptimized (normal) stack frames
	// TODO: I might need to change this later
	j["return_stack_pointer"] = json::object();
	j["return_stack_pointer"]["register"] = "RSP";
	j["return_stack_pointer"]["type"] = "L";
	j["return_stack_pointer"]["offset"] = "8";

	// return_values
	j["return_value"] = json::array();

	for (auto& declaration : return_value_declarations) {
		json jdecl = json::object();

		if (declaration.reg) {
			jdecl["register"] = declaration.reg->name;
			jdecl["type"] = translateType(*declaration.reg->type);
		} else if (declaration.mem_reg) {
			LOG(ERROR) << "Return value is on the stack. Cannot handle this yet...";
			exit(1);
		} else {
			LOG(ERROR) << "Declaration does not deduce an allocation for the return value";
			exit(1);
		}
		j["return_value"].push_back(jdecl);
	}

	j["parameters"] = json::array();

	for (auto& declaration : parameter_declarations) {
		json jdecl = json::object();

		if (declaration.reg) {
			LOG(INFO) << "Register Declaration";
			jdecl["register"] = declaration.reg->name;
			jdecl["type"] = translateType(*declaration.reg->type);
		} else if (declaration.mem_reg) {
			LOG(INFO) << "Stack Declaration";
			jdecl["memory"]["register"] = "RSP";
			jdecl["memory"]["offset"] = declaration.mem_reg->offset;
			jdecl["type"] = translateType(*declaration.mem_reg->type);
		} else {
			LOG(ERROR) << "Declaration does not deduce an allocation for the variable";
			exit(1);
		}

		jdecl["name"] = declaration.name;
		// TODO: make the bindings actually iterate.

		j["parameters"].push_back(jdecl);
	}

	return j;
}


int main(int argc, char *argv[]) {
    google::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);

	std::unique_ptr<CallingConvention> cc(new X86_64_SysV());

	// Allow all log messages for debugging
	// FLAGS_stderrthreshold = 0;

    if (FLAGS_bc_file.empty()) {
        LOG(ERROR) 
            << "Please specify a path to a BITcode input file in --bc_file";
        return EXIT_FAILURE;
    }

	// Overwrite the inherited architecture and os flags if they are not
	// already empty.
	if (!FLAGS_arch.empty() || !FLAGS_os.empty()) {
		LOG(INFO) << "Overwriting architecture and os flags";
		FLAGS_arch = "";
		FLAGS_os = "";
	}

	auto context = new llvm::LLVMContext;
	auto module = remill::LoadModuleFromFile(context, FLAGS_bc_file);

	LOG(INFO) << "Module name: " << module->getName().data();

	std::string arch, os;
	std::tie(arch, os) = getPlatformInformation(module);
	LOG(INFO) << arch << " " << os;

	json j;
	j["arch"] = arch;
	j["os"] = os;

	j["functions"] = json::array();
	for (auto& function : *module) {
		// Skip llvm dbg functions for now
		// TODO: find a way to deal with this
		std::string function_name = function.getName().data();
		if (function_name.find("llvm.") == 0) continue;

		// TODO: remove, only for debugging
		// if (function_name != "void_function") continue;

		LOG(INFO) << "Processing function: " << function.getName().data();
		auto parameter_bindings = cc->bindParameters(function);
		auto return_value_bindings = cc->bindReturnValues(function);
		j["functions"].push_back(outputFunction(function, parameter_bindings, return_value_bindings));
	}

	std::cout << j.dump(4) << std::endl;

	return 0;
}