#!/usr/bin/python3
#
# WelcomeSLN
#
# Copyright (c) 2011 Alexander Preisinger.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# *Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials provided
# with the distribution.
#
# * The names of contributors may not be used to endorse or promote
# products derived from this software without specific prior
# written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AFOREMENTIONED COPYRIGHT HOLDERS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
import io
import os, os.path
import sys
import imp
import uuid
import shutil
import argparse
import xml.etree.ElementTree as etree
_join = os.path.join

## ARGUMENT PARSER ##

def argparsing():
	parser = argparse.ArgumentParser(description="Convert WSLNInfo file into a Visual\
	 Studio Solution and Project.")
	 
	parser.add_argument('-s', '--srcdir', dest="srcdir", metavar="DIR", 
		action="store", default="./", help="Location of the WSLNInfo and Source files.")
	parser.add_argument('-d', '--dstdir', dest="dstdir", metavar="DIR", 
		action="store", default="./MVS", help="Destination of the Visual Studio Solution.")
		
	parser.add_argument('-n', '--no-solution', dest="nosolution", 
		action="store_true", help="Don't generate a Solution file (.sln)")
	
	return parser.parse_args()

def import_WSLNInfo_file(filename):
	
	info = imp.load_source("", filename)
	
	return info

def generate_vcxproj_files(info, path):
	
	xml_template = """<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Debug|Win32">
      <Configuration>Debug</Configuration>
      <Platform>Win32</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|Win32">
      <Configuration>Release</Configuration>
      <Platform>Win32</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <ProjectGuid></ProjectGuid>
    <Keyword>Win32Proj</Keyword>
    <RootNamespace></RootNamespace>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings">
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <LinkIncremental>true</LinkIncremental>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <LinkIncremental>false</LinkIncremental>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <ClCompile>
      <PrecompiledHeader>
      </PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>Disabled</Optimization>
      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
    </ClCompile>
    <Link>
      <SubSystem>Console</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <PrecompiledHeader>
      </PrecompiledHeader>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
    </ClCompile>
    <Link>
      <SubSystem>Console</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
    </Link>
  </ItemDefinitionGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets">
  </ImportGroup>
</Project>

"""
	
	back_path = path;
	
	for proj in info.Projects:
		_f= info.Projects[proj]
		
		path = _join(back_path, proj)
		if not os.path.exists(path):
			os.makedirs(path)
			
		filename = _join(path, proj+".vcxproj")
		
		tmp = open(filename, "w")
		tmp.write(xml_template)
		tmp.close()
		
		tree = etree.ElementTree()
		tree.parse(filename)
		
		root = tree.getroot()
		
		prefix = root.tag.replace("Project", "")

		for element in root.iter():
			if element.tag.endswith("RootNamespace"):
				element.text = proj
			elif element.tag.endswith("ProjectGuid"):
				element.text = "{%s}" % _f["GUID"]

		itemgroup_sources = etree.SubElement(root, prefix+"ItemGroup")
		for source in _f["Sources"]:
			etree.SubElement(itemgroup_sources, prefix+"ClCompile", 
				{"Include" : os.path.basename(source)})

		itemgroup_includes = etree.SubElement(root, prefix+"ItemGroup")
		for include in _f["Includes"]:
			etree.SubElement(itemgroup_includes, prefix+"ClInclude", 
				{"Include" : os.path.basename(include)})

		itemgroup_includes = etree.SubElement(root, prefix+"ItemGroup")
		for include in _f["Resources"]:
			etree.SubElement(itemgroup_includes, prefix+"None", 
				{"Include" : os.path.basename(include)})
		
		tree.write(filename)
		
		tmp = open(filename, "r")
		to_replace = tmp.read()
		tmp.close()
		
		to_replace = to_replace.replace("ns0:", "").replace(":ns0", "")
		tmp = open(filename, "w")
		tmp.write(to_replace)

def generate_sln_file(info, path):
	
	sln_template = """
Microsoft Visual Studio Solution File, Format Version 11.00
# Visual Studio 2010
{Path}
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|Win32 = Debug|Win32
		Release|Win32 = Release|Win32
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{Projects}
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
EndGlobal
"""
	path_template = """
Project("{SolutionGuid}") = "{ProjectName}", "{ProjectName}\{ProjectName}.vcxproj", "{ProjectGuid}"
EndProject
"""
	
	build_template = """
{ProjectGuid}.Debug|Win32.ActiveCfg = Debug|Win32
{ProjectGuid}.Debug|Win32.Build.0 = Debug|Win32
{ProjectGuid}.Release|Win32.ActiveCfg = Release|Win32
{ProjectGuid}.Release|Win32.Build.0 = Release|Win32
"""
	
	path_part = ""
	build_part = ""
	
	
	for proj in info.Projects:
		path_part += path_template.format(SolutionGuid='{%s}' % info.SolutionGUID,
			ProjectName=proj, ProjectGuid=info.Projects[proj]["GUID"])
		build_part += build_template.format(ProjectGuid='{%s}' % info.Projects[proj]["GUID"]) 
		
	
	sln = sln_template.format(Path=path_part,
	                    Projects=build_part,
	                    SolutionGuid='{%s}' % info.SolutionGUID)
	                    
	stream = open(_join(path, info.SolutionName+".sln"), "w")
	stream.write(sln)
	stream.close()
	

def generate_uuids(info):

	for proj in info.Projects:
		if info.Projects[proj]["GUID"] is None:
			info.Projects[proj]["GUID"] = str(uuid.uuid4()).upper()

	if info.SolutionGUID is None:
		info.SolutionGUID = str(uuid.uuid4()).upper()
		
def copy_files(info, src, dst):
	
	for proj in info.Projects:
		_f = info.Projects[proj]
		for base in [_f["Sources"], _f["Includes"], _f["Resources"]]:
			for source in base:
				src_path = _join(src, proj)
				src_path = _join(src_path, source)
				if not os.path.exists(src_path):
					print("File %s doesn't exist." % src_path)
					exit(1)
				
				shutil.copy(src_path, _join(dst, proj))

if __name__ == "__main__":
	args = argparsing()
	info = import_WSLNInfo_file(os.path.join(args.srcdir, "WSLNInfo")) 
	
	
	if not os.path.exists(args.dstdir):
		os.makedirs(args.dstdir)
		
	generate_uuids(info)
	generate_vcxproj_files(info, args.dstdir)

	if not args.nosolution:
		generate_sln_file(info, args.dstdir)
		
	copy_files(info, args.srcdir, args.dstdir)
