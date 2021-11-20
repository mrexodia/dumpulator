CPMAddPackage(
    NAME x64dbg
    URL https://downloads.sourceforge.net/project/x64dbg/snapshots/snapshot_2021-05-08_14-17.zip
    URL_HASH SHA1=a46f3bf3f84fee3b1f7da8949e79d425d7294979
    DOWNLOAD_ONLY ON
)

if(x64dbg_ADDED)
    if(NOT TARGET x64dbg)
        file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS ${x64dbg_SOURCE_DIR}/pluginsdk/*.h)
        add_custom_target(x64dbg-sdk SOURCES ${HEADERS})
        source_group(TREE ${x64dbg_SOURCE_DIR} FILES ${HEADERS})

        add_library(x64dbg INTERFACE)
        target_include_directories(x64dbg INTERFACE ${x64dbg_SOURCE_DIR})
        target_link_directories(x64dbg INTERFACE ${x64dbg_SOURCE_DIR})
    endif()

    function(x64dbg_plugin target)
        if(NOT TARGET ${target})
            # Add plugin dll
            add_library(${target} SHARED ${ARGN})
            # Group source files
            source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${ARGN})
        endif()

        # Change extension
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set_target_properties(${target} PROPERTIES SUFFIX ".dp64")
        else()
            set_target_properties(${target} PROPERTIES SUFFIX ".dp32")
        endif()

        # Link to the x64dbg SDK
        target_link_libraries(${target} PRIVATE x64dbg)

        # Set plugin name based on the target
        target_compile_definitions(${target} PRIVATE "-DPLUGIN_NAME=\"${target}\"")

        # Support PluginDevHelper
        add_custom_command(TARGET ${target} PRE_LINK COMMAND if exist "\"$(SolutionDir)PluginDevBuildTool.exe\"" "(\"$(SolutionDir)PluginDevBuildTool.exe\"" unload "\"$(TargetPath)\")" else (echo Copy PluginDevTool.exe next to the .sln to automatically reload plugins when building))
        add_custom_command(TARGET ${target} POST_BUILD COMMAND if exist "\"$(SolutionDir)PluginDevBuildTool.exe\"" ("\"$(SolutionDir)PluginDevBuildTool.exe\"" reload "\"$(TargetPath)\""))
    endfunction()
endif()