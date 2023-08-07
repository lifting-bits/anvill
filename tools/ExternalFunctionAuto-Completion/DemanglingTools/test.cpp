//this file is a simple tools to use the llvm/Demangle.h to demangle extern_funcs
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <list>
#include <iostream>
#include <fstream>
#include "llvm/Demangle/Demangle.h"
#include "jsoncpp/include/json/json.h"
 

  typedef struct
{
  std::string MangledName;
  std::string BaseName;
  std::string DeclContextName;
  std::string Parameters;
  std::string FunctionName;
  std::string EntireName;
  std::string ReturnType;
  bool hasFunctionQualifiers =false;
  bool isCtorOrDtor =false;
  bool isFunction =false;
  bool isData =false;
  bool isSpecialName =false;
}MangleNode; 

void readFileJson(std::list<std::string>* funclist)
{ 
	Json::Reader reader;
	Json::Value root;

	std::ifstream in("in.json", std::ios::binary);
	if (!in.is_open())
	{
		std::cout << "Error opening file\n";
		return ;
	}
	if (reader.parse(in, root))
	{
        if (root["Function"].isArray())
        {
            int nArraySize = root["Function"].size();  
            for (int i=0; i<nArraySize; i++)
            {       
                std::string funcName = root["Function"][i]["name"].asString();
                funclist->push_back(funcName);  
            }
        }

	}
	else
	{
		std::cout << "parse error\n" << std::endl;
	}
	in.close();

}

MangleNode DemangleFunction(std::string funcName)
{
    MangleNode MNode;
    const char* pcmangledname = funcName.data();
    int size = 0;
    int status = 0;
    char * demangled = NULL;
    char * FunctionReturnType = NULL;
    char * FunctionBaseName = NULL;
    char * demangled4 = NULL;
    char * demangled5 = NULL;
    char * demangled6 = NULL;
	llvm::ItaniumPartialDemangler IPD;

    IPD.partialDemangle(funcName.data());
    MNode.MangledName=funcName;
    MNode.ReturnType= IPD.getFunctionReturnType(NULL, NULL);
    MNode.BaseName= IPD.getFunctionBaseName(NULL, NULL);
    MNode.DeclContextName= IPD.getFunctionDeclContextName(NULL, NULL);
    MNode.FunctionName= IPD.getFunctionName(NULL,NULL);
    MNode.Parameters= IPD.getFunctionParameters(NULL,NULL);
    MNode.EntireName = llvm::itaniumDemangle(funcName.data(), NULL, NULL, &status);
    if(IPD.isCtorOrDtor())
    {
        MNode.isCtorOrDtor=true;
    }
    if(IPD.hasFunctionQualifiers())
    {
        MNode.hasFunctionQualifiers=true;
    }
    if(IPD.isData())
    {
        MNode.isData=true;
    }
    if(IPD.isFunction())
    {
        MNode.isFunction=true;
    }
    if(IPD.isSpecialName())
    {
        MNode.isSpecialName=true;
    }

    return MNode;
    



}





int main ()
{

    std::list<std::string> func_list;
    readFileJson(&func_list);
    std::list<std::string>::iterator iter;
    Json::Value root;
    for(iter=func_list.begin(); iter != func_list.end(); iter++)
    {
        Json::Value bro;
        MangleNode MNode=DemangleFunction(*iter);
        bro["MangledName"]=Json::Value(MNode.MangledName);
        bro["BaseName"]=Json::Value(MNode.BaseName);
        bro["DeclContextName"]=Json::Value(MNode.DeclContextName);
        bro["Parameters"]=Json::Value(MNode.Parameters);
        bro["ReturnType"]=Json::Value(MNode.ReturnType);
        bro["FunctionName"]=Json::Value(MNode.FunctionName);
        bro["EntireName"]=Json::Value(MNode.EntireName);
        bro["hasFunctionQualifiers"]=Json::Value(MNode.hasFunctionQualifiers);
        bro["isCtorOrDtor"]=Json::Value(MNode.isCtorOrDtor);
        bro["isFunction"]=Json::Value(MNode.isFunction);
        bro["isData"]=Json::Value(MNode.isData);
        bro["isSpecialName"]=Json::Value(MNode.isSpecialName);

        root["Function"].append(Json::Value(bro));
    }
    std::ofstream os;
	os.open("out.json", std::ios::out);
    Json::StyledWriter sw;
    if (!os.is_open())
	{
		std::cout << "error:can't find the file" << std::endl;
	}
	os << sw.write(root);
	os.close();





    
    


	

	
	//free(demangled);
	
  return 0;
}