#include <sstream>
#include <string>
#include <iostream>
#include <algorithm>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Type.h>

#include <remill/BC/Util.h>

#include "json.hpp"

// for convenience
using json = nlohmann::json;

DECLARE_string(arch);
DECLARE_string(os);

DEFINE_string(bc_file, "", "Path to bitcode file containing data to be specified");


std::string translateType(llvm::Type& type) {
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
json processFunction(llvm::Function& func) {
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

	if (func.arg_begin() != func.arg_end()) {
		LOG(INFO) << "    " << "Argument Types:";
	}
	for (auto& arg : func.args()) {
		json jfunc = json::object();
		jfunc["register"] = "UNIMPLEMENTED";
		jfunc["type"] = translateType(*arg.getType());
		jfunc["name"] = "UNIMPLMENTED";
		
		j["parameters"].push_back(jfunc);
	}

	return j;
}


int main(int argc, char *argv[]) {
    google::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);

	// Allow all log messages for debugging
	// FLAGS_stderrthreshold = 0;

    if (FLAGS_bc_file.empty()) {
        LOG(ERROR) 
            << "Please specify a path to a bitcode input file in --bc_file";
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
		j["functions"].push_back(processFunction(function));
	}

	std::cout << j.dump(4) << std::endl;

	return 0;
}