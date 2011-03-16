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
	
	return parser.parse_args()

def import_WSLNInfo_file(filename):
	
	info = imp.load_source("", filename)
	
	return info

def generate_vcxproj_file(info, path):
	
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
</Project>"""
	
	path = _join(path, info.ProjectName)
	if not os.path.exists(path):
		os.makedirs(path)
		
	filename = _join(path, info.ProjectName+".vcxproj")
	
	tmp = open(filename, "w")
	tmp.write(xml_template)
	tmp.close()
	
	tree = etree.ElementTree()
	tree.parse(filename)
	
	root = tree.getroot()
	
	prefix = root.tag.replace("Project", "")

	for element in root.iter():
		if element.tag.endswith("RootNamespace"):
			element.text = info.ProjectName
		elif element.tag.endswith("ProjectGuid"):
			element.text = "{%s}" % info.ProjectGuid

	itemgroup_sources = etree.SubElement(root, prefix+"ItemGroup")
	for source in info.Sources:
		etree.SubElement(itemgroup_sources, prefix+"ClCompile", {"Include" : source})

	itemgroup_includes = etree.SubElement(root, prefix+"ItemGroup")
	for include in info.Includes:
		etree.SubElement(itemgroup_includes, prefix+"ClInclude", {"Include" : include})
	
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
Project("{SolutionGuid}") = "{ProjectName}", "{ProjectName}\{ProjectName}.vcxproj", "{ProjectGuid}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|Win32 = Debug|Win32
		Release|Win32 = Release|Win32
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{ProjectGuid}.Debug|Win32.ActiveCfg = Debug|Win32
		{ProjectGuid}.Debug|Win32.Build.0 = Debug|Win32
		{ProjectGuid}.Release|Win32.ActiveCfg = Release|Win32
		{ProjectGuid}.Release|Win32.Build.0 = Release|Win32
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
EndGlobal
"""
	sln = sln_template.format(ProjectName=info.ProjectName,
	                    ProjectGuid='{%s}' % info.ProjectGuid,
	                    SolutionGuid='{%s}' % info.SolutionGuid)
	                    
	stream = open(_join(path, info.ProjectName+".sln"), "w")
	stream.write(sln)
	stream.close()
	

def generate_uuids(info):
	
	if info.ProjectGuid is None:
		info.ProjectGuid = str(uuid.uuid4()).upper()

	if info.SolutionGuid is None:
		info.SolutionGuid = str(uuid.uuid4()).upper()
		
def copy_files(info, src, dst):
	
	for base in [info.Sources, info.Includes]:
		for source in base:
			src_path = _join(src, source)
			if not os.path.exists(src_path):
				print("File %s doesn't exist." % src_path)
				exit(1)
			
			shutil.copy(src_path, _join(dst, info.ProjectName))

if __name__ == "__main__":
	args = argparsing()
	info = import_WSLNInfo_file(os.path.join(args.srcdir, "WSLNInfo")) 
	if not os.path.exists(args.dstdir):
		os.makedirs(args.dstdir)
	generate_uuids(info)
	generate_vcxproj_file(info, args.dstdir)
	generate_sln_file(info, args.dstdir)
	copy_files(info, args.srcdir, args.dstdir)
