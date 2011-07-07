; Script generated by the HM NIS Edit Script Wizard.

; HM NIS Edit Wizard helper defines
!define PRODUCT_NAME "Host sFlow Agent"
!define PRODUCT_PUBLISHER "Host sFlow Project"
!define PRODUCT_WEB_SITE "http://host-sflow.sourceforge.net/"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\hsflowd.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; MUI 1.67 compatible ------
!include "MUI.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall-blue.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; Directory page
!insertmacro MUI_PAGE_DIRECTORY

page custom get_collector write_collector


; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!insertmacro MUI_PAGE_FINISH

Function get_collector
  # If you need to skip the page depending on a condition, call Abort.
  ReserveFile "collector.ini"
  !insertmacro MUI_INSTALLOPTIONS_EXTRACT "collector.ini"
  !insertmacro MUI_INSTALLOPTIONS_DISPLAY "collector.ini"
FunctionEnd

Function write_collector
  # Form validation here. Call Abort to go back to the page.
  # Use !insertmacro MUI_INSTALLOPTIONS_READ $Var "InstallOptionsFile.ini" ...
  # to get values.
  !insertmacro MUI_INSTALLOPTIONS_READ $R0 "collector.ini" "Field 1" "State"
FunctionEnd

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; MUI end ------

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile ${OUT_FILE}
InstallDir "$PROGRAMFILES\Host sFlow Project\Host sFlow Agent"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

Section "MainSection" SEC01
  nsSCM::Stop "hsflowd"
  nsSCM::Remove "hsflowd"
  call CallMsiDeinstaller
  SetOutPath "$INSTDIR"
  SetOverwrite ifnewer
  File ${BUILD_DIR}\hsflowd.exe
  CreateDirectory "$SMPROGRAMS\\"
  # install service
  nsSCM::Install /NOUNLOAD "hsflowd" "Host sFlow Agent" 16 2 "$INSTDIR\hsflowd.exe" "" "" "" ""
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\hsflowd\Parameters" "collector" $R0
  nsSCM::Start /NOUNLOAD "hsflowd"
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\hsflowd.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\hsflowd.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  
SectionEnd


Function un.onUninstSuccess
  HideWindow
  MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) was successfully removed from your computer."
FunctionEnd

Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
  Abort
FunctionEnd

Section Uninstall
  nsSCM::Stop "hsflowd"
  nsSCM::Remove "hsflowd"
  Delete "$INSTDIR\uninst.exe"
  Delete "$INSTDIR\hsflowd.exe"

  RMDir "$SMPROGRAMS\\"
  RMDir "$INSTDIR"

  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose true
SectionEnd

!define OLDVERSIONWARNING \
  "An older version of $(^Name) was found on your system. It is recommended that you uninstall the old version before installing the new version.$\r$\n$\r$\nDo you want to uninstall the old version of $(^Name)?"
!define OLDVERSIONREMOVEERROR \
  "A problem was encountered while removing the old version of $(^Name). Please uninstall it manually using Programs and Features in Control Panel."
 
 
!define INSTALLSTATE_DEFAULT "5"
!define INSTALLLEVEL_MAXIMUM "0xFFFF"
!define INSTALLSTATE_ABSENT "2"
!define ERROR_SUCCESS "0"
 
 
Function CallMsiDeinstaller
  System::Call "msi::MsiQueryProductStateA(t '{1E7B7EE6-2A59-4FCD-B4F8-2679CCB92DC7}') i.r0"
  StrCmp $0 "${INSTALLSTATE_DEFAULT}" 0 Done
 
  MessageBox MB_YESNO|MB_ICONQUESTION "${OLDVERSIONWARNING}" \
  IDNO Done
 
  System::Call "msi::MsiConfigureProductA(t '{1E7B7EE6-2A59-4FCD-B4F8-2679CCB92DC7}', \
    i ${INSTALLLEVEL_MAXIMUM}, i ${INSTALLSTATE_ABSENT}) i.r0"
  StrCmp $0 ${ERROR_SUCCESS} Done
 
    MessageBox MB_OK|MB_ICONEXCLAMATION \
    "${OLDVERSIONREMOVEERROR}"
  Done:
FunctionEnd