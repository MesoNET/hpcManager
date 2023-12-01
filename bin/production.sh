#!/bin/bash

betaRegex='Beta.sh$'
toolPath="$(dirname "$(readlink -f "$(which "${0}")")")"
settingsFile="${toolPath}/../config/binSettings.sh"
if [[ -f "${settingsFile}" ]]
then
  source ${settingsFile}
  if ! [[ "${hpcManagerRootFolder}" == "${hpcManagerFolder}" || "${hpcManagerRootFolder}" == "${hpcManagerBetaFolder}" ]]
  then
    echo "Manager folder '${hpcManagerRootFolder}' not allowed in config file (${settingsFile})."
    exit 1
  fi
else
  echo "Unable to find setting file (${settingsFile})."
  exit 1
fi

defaultFoldersPermissions="u=rwx,g=rx,o-rwxs"
defaultFilesPermissions="u=rw,g=r,o-rwxs"
defaultUserOwner="root"
defaultGroupOwner="${adminGroup}"
hpcManagerRootFolderRegex='^/[^/]+/[^/]+/[^/]+/python-hpcManager-(stable|beta)$'

if [[ "${hpcManagerRootFolder}" =~ ${hpcManagerRootFolderRegex} ]]
then
    echo "Root folder set to : ${hpcManagerRootFolder}"
    echo "Set default folders permissions (${defaultFoldersPermissions}) ..."
    find ${hpcManagerRootFolder} -type d -exec chmod ${defaultFoldersPermissions} '{}' \;
    echo "Set default files permissions (${defaultFilesPermissions}) ..."
    find ${hpcManagerRootFolder} -type f -exec chmod ${defaultFilesPermissions} '{}' \;
    echo "Set default user (${defaultUserOwner}) and group (${defaultGroupOwner}) owners ..."
    find ${hpcManagerRootFolder} -exec chown ${defaultUserOwner}.${defaultGroupOwner} '{}' \;
    echo "Set execution permissions on bin files ..."
    find ${hpcManagerRootFolder}/bin -type f -name "hpc*" -exec chmod ug+x '{}' \;
else
  echo "Bad root folder '${hpcManagerRootFolder}'"
fi