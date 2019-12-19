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

#include <remill/BC/Util.h>

#include "json.hpp"

struct AllocationBinding;
struct RegisterConstraint;

// forward declarations for now TODO: change this
std::unique_ptr<AllocationBinding> tryRegisterAllocate(const llvm::Argument& argument, std::vector<bool>& reserved, const std::vector<RegisterConstraint>& register_constraints);
std::string translateType(const llvm::Type& type);

// for convenience
using json = nlohmann::json;

DECLARE_string(arch);
DECLARE_string(os);

DEFINE_string(bc_file, "", "Path to BITcode file containing data to be specified");

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

// TODO: support the stack later
struct AllocationBinding {
	AllocationBinding() {}
	AllocationBinding(std::string _register_name, std::string _variable_name, std::string _variable_type)
		: register_name(_register_name), variable_name(_variable_name), variable_type(_variable_type) {}

	std::string register_name;
	std::string variable_name;
	std::string variable_type; // TODO change this from a std::string later
};

struct ParameterPasses {};
struct ReturnPasses {};

class CallingConvention {
public:
	CallingConvention(llvm::CallingConv::ID _identity) : identity(_identity){}
	virtual ~CallingConvention() {}

	virtual std::vector<AllocationBinding> bindParameters(const llvm::Function& function) = 0;
	virtual void bindReturnValue() = 0;

	llvm::CallingConv::ID getIdentity() { return identity; }

private:
	llvm::CallingConv::ID identity;
};


class X86_64_SysV : public CallingConvention {
public:
	X86_64_SysV() :CallingConvention(llvm::CallingConv::X86_64_SysV) {}
	~X86_64_SysV() {}
	
	std::vector<AllocationBinding> bindParameters(const llvm::Function& function) {
		std::vector<AllocationBinding> bindings;
		std::vector<bool> reserved(register_constraints.size(), false);

		for (auto& argument : function.args()) {
			const llvm::Type& type = *argument.getType();
			if (auto bindptr = tryRegisterAllocate(argument, reserved, register_constraints)) {
				bindptr->variable_type = translateType(type);
				std::cout << bindptr->register_name << " " << bindptr->variable_type << std::endl;
				bindings.push_back(*bindptr);
			}
		}
		return bindings;
	}

	void bindReturnValue() {
		std::cout << "Yay" << std::endl;
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
std::unique_ptr<AllocationBinding> tryRegisterAllocate(const llvm::Argument& argument, std::vector<bool>& reserved, const std::vector<RegisterConstraint>& register_constraints) {
	const llvm::Type& type = *argument.getType();

	std::unique_ptr<AllocationBinding> allocation_binding(new AllocationBinding);

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
	}

	for (size_t i = 0; i < register_constraints.size(); i++) {
		const RegisterConstraint& constraint = register_constraints[i];
		if (reserved[i]) {
			continue;
		}
		
		if (size_constraint & constraint.size_constraint && type_constraint & constraint.type_constraint) {
			reserved[i] = true;
			allocation_binding->register_name = constraint.register_name;
			return allocation_binding;
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
json outputFunction(llvm::Function& func, std::vector<AllocationBinding> bindings) {
	json j;
	j["name"] = func.getName().data();

	// TODO: change this because it is specific to x86_64 normal
	// (unoptimized) stack frames.
	j["return_stack_pointer"] = json::object();
	j["return_stack_pointer"]["register"] = "RSP";
	j["return_stack_pointer"]["type"] = "L";
	j["return_stack_pointer"]["offset"] = "8";

	// return_values
	j["return_value"] = json::object();
	j["return_value"]["register"] = "UNIMPLEMENTED";
	j["return_value"]["type"] = translateType(*func.getReturnType());
	j["return_value"]["name"] = "UNIMPLEMENTED";

	j["parameters"] = json::array();

	size_t i = 0;
	for (auto& arg : func.args()) {
		json jfunc = json::object();

		jfunc["register"] = bindings[i].register_name;
		jfunc["type"] = translateType(*arg.getType());
		jfunc["name"] = bindings[i].variable_name;
		// TODO: make the bindings actually iterate.

		j["parameters"].push_back(jfunc);
	}

	return j;
}


int main(int argc, char *argv[]) {
    google::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);

	std::unique_ptr<CallingConvention> cc(new X86_64_SysV());
	cc->bindReturnValue();

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
		if (function.getName() == "dummy_function") {
			auto bindings = cc->bindParameters(function);
			std::cout << outputFunction(function, bindings).dump(4) << std::endl;
		}
	}

	std::cout << j.dump(4) << std::endl;

	return 0;
}