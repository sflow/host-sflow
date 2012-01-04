!define PRODUCT_NAME "Host sFlow Agent"
!define PRODUCT_PUBLISHER "Host sFlow Project"
!define PRODUCT_WEB_SITE "http://host-sflow.sourceforge.net/"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\hsflowd.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"
!define EXTENSION_DIR "Extension"
!define SERVICE_NAME "hsflowd"
!define SFLOW_PARAMS_KEY "SYSTEM\CurrentControlSet\Services\hsflowd\Parameters"
!searchparse /file "../version.h" 'VERSION_MAJOR ' VERSION_MAJOR
!searchparse /file "../version.h" 'VERSION_MINOR ' VERSION_MINOR
!searchparse /file "../version.h" 'VERSION_REVISION ' VERSION_REVISION
!define VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_REVISION}"

!include "MUI2.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_NOAUTOCLOSE true
!define MUI_UNFINISHPAGE_NOAUTOCLOSE true

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
!insertmacro MUI_PAGE_LICENSE "license.rtf"
; Directory page
!insertmacro MUI_PAGE_DIRECTORY

Var sflowDialog
Var collectorLabel
Var collectorText
Var collector
Var pollingLabel
Var pollingNumber
Var pollingInterval
Var samplingLabel
Var samplingNumber
Var samplingRate
Var hyperVExtension

Page custom setSFlowParams saveSFlowParams

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

Function .onInit
    StrCpy $hyperVExtension "0"
    ReadRegStr $collector HKLM "${SFLOW_PARAMS_KEY}" "collector"
    ReadRegDWORD $pollingInterval HKLM "${SFLOW_PARAMS_KEY}" "pollingInterval"
    ReadRegDWORD $samplingRate HKLM "${SFLOW_PARAMS_KEY}" "samplingRate"
    ${If} $collector == ""
        StrCpy $collector "localhost"
    ${EndIf}
    ${If} $pollingInterval == ""
        StrCpy $pollingInterval "20"
    ${EndIf}
    ${If} $samplingRate == ""
        StrCpy $samplingRate "256"
    ${EndIf}
    !ifdef EXTENSION
        # Get Windows version
        Version::GetWindowsVersion
        Pop $0   # Major version
        Pop $1   # Minor version
        Pop $2   # Build number
        Pop $2   # PlatformID
        Pop $2   # CSDVersion
        ${If} $0 >= 6
        ${AndIf} $1 >= 2
            # Windows 8 - now test for Hyper-V
            nsSCM::QueryStatus /NOUNLOAD "vmms"
            Pop $0
            Pop $1
            ${If} $0 = 0
            ${AndIf} $1 <> 1
            ${AndIf} $1 <> 3
                StrCpy $hyperVExtension "1"
            ${EndIf}
        ${EndIf}
    !endif
FunctionEnd

Function setSFlowParams
    !insertmacro MUI_HEADER_TEXT "Set sampling parameters" "Set the sFlow collector address and sampling parameters"
    nsDialogs::Create 1018
	Pop $sflowDialog
    ${If} $sflowDialog == error
		Abort
	${EndIf}
    ${NSD_CreateLabel} 5u 24u 100u 15u "sFlow collector:"
	Pop $collectorLabel
    ${NSD_AddStyle} $collectorLabel ${SS_RIGHT}
	${NSD_CreateText} 110u 22u 130u 15u $collector
	Pop $collectorText
    ${NSD_CreateLabel} 5u 42u 100u 15u "Counter polling interval (s):"
	Pop $pollingLabel
    ${NSD_AddStyle} $pollingLabel ${SS_RIGHT}
	${NSD_CreateNumber} 110u 40u 50u 15u $pollingInterval
	Pop $pollingNumber
    ${If} $hyperVExtension = 1
        ${NSD_CreateLabel} 5u 60u 100u 15u "Sampling rate:"
    	Pop $samplingLabel
        ${NSD_AddStyle} $samplingLabel ${SS_RIGHT}
	    ${NSD_CreateNumber} 110u 58u 50u 15u $samplingRate
	    Pop $samplingNumber
    ${Endif}
    nsDialogs::Show
FunctionEnd

Function saveSFlowParams
    ${NSD_GetText} $collectorText $collector
    ${NSD_GetText} $pollingNumber $pollingInterval
    ${NSD_GetText} $samplingNumber $samplingRate
FunctionEnd

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; MUI end ------

# Function to stop and delete the host sFlow service.
# nsSCM::Stop returns before the service is actually dead
# so a loop testing that the application mutex has gone is
# necessary. The macro works round the NSIS limitation that
# a function cannot be shared between installer and uninstaller.

!macro stopAndDeleteService un
    Function ${un}stopAndDeleteService
        DetailPrint "Stopping sFlow service"
        nsSCM::Stop /NOUNLOAD "${SERVICE_NAME}"
        StrCpy $R1 0
        wait:
            # Try to get the mutex - if this succeeds, we are still running
            System::Call 'kernel32::OpenMutex(i 0x100000, b 0, t "Global\hsflowd-{0C4FB5D9-641D-428C-8216-950962E608E0}") i .R0'
            IntCmp $R0 0 waitdone
            System::Call 'kernel32::CloseHandle(i $R0)'
            IntOp $R1 $R1 + 1
            # Loop a maximum of 5 times
            IntCmp $R1 5 cannotKill
            Sleep 500
            goto wait
        cannotKill:
            MessageBox MB_OK "Cannot stop service. Please ensure that all instances of hsflowd are stopped, and try again."
            Quit
        waitdone:
            nsSCM::Remove /NOUNLOAD "${SERVICE_NAME}"
    FunctionEnd
!macroend

!insertmacro stopAndDeleteService ""
!insertmacro stopAndDeleteService "un."

Name "${PRODUCT_NAME} v${VERSION}"
OutFile "${OUTPUT_ROOT}-${VERSION}-${PLATFORM}.exe"
!if ${PLATFORM} == "x64"
    InstallDir "$PROGRAMFILES64\Host sFlow Project\Host sFlow Agent"
!else
    InstallDir "$PROGRAMFILES\Host sFlow Project\Host sFlow Agent"
!endif
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show
RequestExecutionLevel admin

Section "Install host sFlow" SEC01
    # Uninstall a legacy version (probably never found now)
    Push "{1E7B7EE6-2A59-4FCD-B4F8-2679CCB92DC7}"
    call CallMsiDeinstaller
    # Uninstall abother legacy version (probably never found now)
    Push "{965FAE0A-0935-4D68-BAFB-BF2F9CA16476}"
    call CallMsiDeinstaller
    # Uninstall a version installed with the current MSI installer
    Push "{74FFB15C-03C1-4B7D-809F-939A5C57F659}"
    call CallMsiDeinstaller
    # Stop an existing service
    call stopAndDeleteService
    # Perform the installation
    SetOutPath "$INSTDIR"
    SetOverwrite on
    # Install the service executable
    File "${BUILD_DIR}\hsflowd.exe"
    !ifdef EXTENSION
        ${If} $hyperVExtension = 1
            # Install the switch extension
            SetOutPath "$INSTDIR\${EXTENSION_DIR}"
            File "${BUILD_DIR}\sflowfilter.inf"
            File "${BUILD_DIR}\sflowfilter.sys"
            File "${BUILD_DIR}\sflowfilter.cat"
            # Install the extension installer helper app
            File "${BUILD_DIR}\protinst.exe"
            # Try to uninstall an existing switch extension
            DetailPrint "Uninistalling previous sFlow virtual switch extension"
            nsExec::ExecToLog '"$INSTDIR\${EXTENSION_DIR}\protinst.exe" -q -u sflowfilter'
        ${EndIf}
    !endif
    # Save the sFlow parameters
    WriteRegStr HKLM "${SFLOW_PARAMS_KEY}" "collector" $collector
    WriteRegDWORD HKLM "${SFLOW_PARAMS_KEY}" "pollingInterval" $pollingInterval
    WriteRegDWORD HKLM "${SFLOW_PARAMS_KEY}" "samplingRate" $samplingRate
    !ifdef EXTENSION
        ${If} $hyperVExtension = 1
            # Install the new switch extension
            DetailPrint "Installing sFlow virtual switch extension"
            nsExec::ExecToLog '"$INSTDIR\${EXTENSION_DIR}\protinst.exe" -i sflowfilter "$INSTDIR\${EXTENSION_DIR}\sflowfilter.inf"'
        ${EndIf}
    !endif
    DetailPrint "Installing and starting sFlow service"
    # Install and start the service
    nsSCM::Install /NOUNLOAD "${SERVICE_NAME}" "Host sFlow Agent" 16 2 "$INSTDIR\hsflowd.exe" "" "" "" ""
    Pop $0
    nsSCM::Start /NOUNLOAD "${SERVICE_NAME}"
    Pop $0
SectionEnd

Section -Post
    WriteUninstaller "$INSTDIR\uninst.exe"
    WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\hsflowd.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\hsflowd.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${VERSION}"
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
    # Stop and remove the service
    call un.stopAndDeleteService
    !ifdef EXTENSION
        # Uninstall the switch extension
        DetailPrint "Uninstalling sFlow virtual switch Extension"
        nsExec::ExecToLog '"$INSTDIR\${EXTENSION_DIR}\protinst.exe" -q -u sflowfilter'
        # Delete installed files
        Delete "$INSTDIR\${EXTENSION_DIR}\sflowfilter.inf"
        Delete "$INSTDIR\${EXTENSION_DIR}\sflowfilter.sys"
        Delete "$INSTDIR\${EXTENSION_DIR}\sflowfilter.cat"
        Delete "$INSTDIR\${EXTENSION_DIR}\protinst.exe"
        RMDir "$INSTDIR\${EXTENSION_DIR}"
    !endif
    Delete "$INSTDIR\uninst.exe"
    Delete "$INSTDIR\hsflowd.exe"
    RMDir "$INSTDIR"
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
SectionEnd

!define OLDVERSIONWARNING \
    "An older version of ${PRODUCT_NAME} was found on your system. It is recommended that you uninstall the old version before installing the new version.$\r$\n$\r$\nDo you want to uninstall the old version of ${PRODUCT_NAME}?"
!define OLDVERSIONREMOVEERROR \
    "A problem was encountered while removing the old version of ${PRODUCT_NAME}. Please uninstall it manually using Programs and Features in Control Panel."

!define INSTALLSTATE_DEFAULT "5"
!define INSTALLLEVEL_MAXIMUM "0xFFFF"
!define INSTALLSTATE_ABSENT "2"
!define ERROR_SUCCESS "0"

Function CallMsiDeinstaller
    Pop $1
    System::Call "msi::MsiQueryProductStateA(t r1) i.r0"
    StrCmp $0 "${INSTALLSTATE_DEFAULT}" 0 done
    MessageBox MB_YESNO|MB_ICONQUESTION "${OLDVERSIONWARNING}" IDNO done
    System::Call "msi::MsiConfigureProductA(t r1, \
        i ${INSTALLLEVEL_MAXIMUM}, i ${INSTALLSTATE_ABSENT}) i.r0"
    StrCmp $0 ${ERROR_SUCCESS} done
    MessageBox MB_OK|MB_ICONEXCLAMATION "${OLDVERSIONREMOVEERROR}"
    done:
FunctionEnd