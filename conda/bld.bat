@echo off
REM bld.bat - For Windows builds

REM Create the target directories
if not exist "%PREFIX%\bin" mkdir "%PREFIX%\bin"
if not exist "%PREFIX%" mkdir "%PREFIX%"

REM Copy the DLL and plugin file
copy bin\plugify-plugin-permissions.dll "%PREFIX%\bin\" || exit 1
copy plugify-plugin-permissions.pplugin "%PREFIX%\" || exit 1

REM Create activation scripts
if not exist "%PREFIX%\etc\conda\activate.d" mkdir "%PREFIX%\etc\conda\activate.d"
if not exist "%PREFIX%\etc\conda\deactivate.d" mkdir "%PREFIX%\etc\conda\deactivate.d"

REM Create activation script
echo @echo off > "%PREFIX%\etc\conda\activate.d\plugify-plugin-permissions.bat"
echo set "PLUGIFY_PERMISSIONS_PLUGIN_PATH=%%CONDA_PREFIX%%;%%PLUGIFY_PERMISSIONS_PLUGIN_PATH%%" >> "%PREFIX%\etc\conda\activate.d\plugify-plugin-permissions.bat"

REM Create deactivation script  
echo @echo off > "%PREFIX%\etc\conda\deactivate.d\plugify-plugin-permissions.bat"
echo set "PLUGIFY_PERMISSIONS_PLUGIN_PATH=%%PLUGIFY_PERMISSIONS_PLUGIN_PATH:%%CONDA_PREFIX%%;=%%" >> "%PREFIX%\etc\conda\deactivate.d\plugify-plugin-permissions.bat"

exit 0
