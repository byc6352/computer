unit uSvc;

interface
uses windows,winsvc,uStr;
type
  //******************************************************************************
  TEnumServices = array[0..0] of TEnumServiceStatus;
  PEnumServices = ^TEnumServices;

  pServiceStatus=^stServiceStatus;
  stServiceStatus=record
    ServiceType:array[0..63] of ansiChar;
    CurrentState:array[0..63] of ansiChar;
    ControlsAccepted:array[0..63] of ansiChar;
    Win32ExitCode:array[0..63] of ansiChar;
    ServiceSpecificExitCode:array[0..63] of ansiChar;
    CheckPoint:array[0..63] of ansiChar;
    WaitHint:array[0..63] of ansiChar;
  end;
  PServiceConfig=^stServiceConfig;
  stServiceConfig=record
    ServiceType:array[0..63] of ansiChar;
    StartType:array[0..63] of ansiChar;
    ErrorControl:array[0..63] of ansiChar;
    BinaryPathName:array[0..max_path] of ansiChar;
    ServiceDll:array[0..max_path] of ansiChar;
    LoadOrderGroup:array[0..63] of ansiChar;
    TagId:array[0..63] of ansiChar;
    Dependencies:array[0..63] of ansiChar;
    ServiceStartName:array[0..63] of ansiChar;
    DisplayName:array[0..127] of ansiChar;
    Description:array[0..255] of ansiChar;
  end;
  pServiceInfo=^stServiceInfo;
  stServiceInfo=record
    ID:array[0..3] of ansiChar;
    ServiceName:array[0..63] of ansiChar;
    DisplayName:array[0..127] of ansiChar;
    ServiceStatus:stServiceStatus;
    ServiceConfig:stServiceConfig;
  end;
  PServicesInfo=^TServicesInfo;
  TServicesInfo=array[0..0] of stServiceInfo;
//*****************************************************************************

function DisableSvc(ServiceName: pansiChar):BOOL;
function UnRegSvc(ServiceName:pansiChar):BOOL;
function EnumServices(const uType,dwServiceState:DWORD;var FServicesInfo:PServicesInfo;var FServiceCount:DWORD):BOOL;
function TranslateServiceState(ss:SERVICE_STATUS):stServiceStatus;
function TranslateServiceConfig(QS:QUERY_SERVICE_CONFIGA):stServiceConfig;
function GetServiceDll(ServiceName,ServiceDll:pansiChar):pansiChar;
function DesktopSvc(ServiceName: pansiChar;bEnable:BOOL):BOOL;
function RunSvc(ServiceName: pansiChar): BOOL;
function StopSvc(ServiceName: pansiChar): BOOL;
function ShutdownSvc(ServiceName: pansiChar): BOOL;
function EnableSvc(ServiceName:pansiChar):BOOL;
  //************************************************************************
var
  svcName:string;
  //hDLL:cardinal;
implementation
//****************************************************************************
function DesktopSvc(ServiceName: pansiChar;bEnable:BOOL):BOOL;
var
  scm,svc:SC_HANDLE;
  ServiceStatus:SERVICE_STATUS;
  ServiceType:DWORD;
begin
  result:=false;
  scm:=OpenSCManager(nil,nil,SC_MANAGER_ALL_ACCESS);
  if (scm<>0) then
  begin
    svc:=OpenServiceA(scm,servicename,SERVICE_ALL_ACCESS);
    if (svc<>0) then
    begin
       if bEnable then
         ServiceType:=SERVICE_WIN32_SHARE_PROCESS or SERVICE_INTERACTIVE_PROCESS
       else
         ServiceType:=SERVICE_WIN32_SHARE_PROCESS;
      if ChangeServiceConfig(svc,
        ServiceType,
        SERVICE_NO_CHANGE,
        SERVICE_NO_CHANGE,
        nil,nil,nil,nil,nil,nil,nil) then
        result:=true
      else
        result:=false;
      CloseServiceHandle(svc);
    end;
       CloseServiceHandle(scm);
  end;//if
end;
function UnRegSvc(ServiceName:pansiChar):BOOL;
//06-05-14:注消服务而不关闭服务
var
  scm,svc:SC_HANDLE;
  ServiceStatus:SERVICE_STATUS;
begin
  result:=false;
  scm:=OpenSCManager(nil,nil,SC_MANAGER_CONNECT);
  if (scm<>0) then
  begin
    svc:=OpenServiceA(scm,servicename,SERVICE_ALL_ACCESS);
    if (svc<>0) then
    begin
    {
      QueryServiceStatus(svc,ServiceStatus);
      if (ServiceStatus.dwCurrentState=SERVICE_RUNNING) then
        ControlService(svc,SERVICE_CONTROL_STOP,ServiceStatus);
        }
      result:=DeleteService(svc);
      CloseServiceHandle(svc);
    end;
       CloseServiceHandle(scm);
  end;//if
end;
function DisableSvc(ServiceName: pansiChar):BOOL;
var
  scm,svc:SC_HANDLE;
  ServiceStatus:SERVICE_STATUS;
begin
  result:=false;
  scm:=OpenSCManager(nil,nil,SC_MANAGER_ALL_ACCESS);
  if (scm<>0) then
  begin
    svc:=OpenServiceA(scm,servicename,SERVICE_ALL_ACCESS);
    if (svc<>0) then
    begin
      QueryServiceStatus(svc,ServiceStatus);
      //if (ServiceStatus.dwCurrentState=SERVICE_RUNNING) then
      //  ControlService(svc,SERVICE_CONTROL_STOP,ServiceStatus);
      if ChangeServiceConfig(svc,
        SERVICE_NO_CHANGE,
        SERVICE_DISABLED,
        SERVICE_NO_CHANGE,
        nil,nil,nil,nil,nil,nil,nil) then
        result:=true
      else
        result:=false;
      CloseServiceHandle(svc);
    end;
       CloseServiceHandle(scm);
  end;//if
end;
function EnableSvc(ServiceName:pansiChar):BOOL;
var
  scm,svc:SC_HANDLE;
  ServiceStatus:SERVICE_STATUS;
  p:pansiChar;
begin
  result:=false;
  scm:=OpenSCManager(nil,nil,SC_MANAGER_ALL_ACCESS);
  if (scm<>0) then
  begin
    svc:=OpenServiceA(scm,servicename,SERVICE_ALL_ACCESS);
    if (svc<>0) then
    begin
      QueryServiceStatus(svc,ServiceStatus);
      if (ServiceStatus.dwCurrentState=SERVICE_RUNNING) then
        ControlService(svc,SERVICE_CONTROL_STOP,ServiceStatus);
      if ChangeServiceConfig(svc,
        SERVICE_NO_CHANGE,
        SERVICE_AUTO_START,
        SERVICE_NO_CHANGE,
        nil,nil,nil,nil,nil,nil,nil) then
        result:=true
      else
        result:=false;
      StartServiceA(svc, 0, P);
      CloseServiceHandle(svc);
    end;
       CloseServiceHandle(scm);
  end;//if
end;
function ShutdownSvc(ServiceName: pansiChar): BOOL;
var
  SCM, SCH: SC_Handle;
  ServiceStatus: TServiceStatus;
begin
  Result := False;
  SCM := OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
  if SCM <> 0 then
  begin
    SCH := OpenServiceA(SCM, ServiceName, SERVICE_ALL_ACCESS);
    if SCH <> 0 then
    begin
      Result := ControlService(SCH, SERVICE_CONTROL_SHUTDOWN,
        ServiceStatus);
      CloseServiceHandle(SCH);
    end;
    CloseServiceHandle(SCM);
  end;
end;
function StopSvc(ServiceName: pansiChar): BOOL;
var
  SCM, SCH: SC_Handle;
  ServiceStatus: TServiceStatus;
begin
  Result := False;
  SCM := OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
  if SCM <> 0 then
  begin
    SCH := OpenServiceA(SCM, ServiceName, SERVICE_ALL_ACCESS);
    if SCH <> 0 then
    begin
      Result := ControlService(SCH, SERVICE_CONTROL_STOP, ServiceStatus);
      CloseServiceHandle(SCH);
    end;
    CloseServiceHandle(SCM);
  end;
end;
function RunSvc(ServiceName: pansiChar): BOOL;
var
  SCM, SCH: SC_Handle;
  P: PansiChar;
begin
  Result := False;
  SCM := OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
  if SCM <> 0 then
  begin
    SCH := OpenServiceA(SCM,ServiceName, SERVICE_ALL_ACCESS);
    if SCH <> 0 then
    begin
      Result := StartServiceA(SCH, 0, P);
      CloseServiceHandle(SCH);
    end;
    CloseServiceHandle(SCM);
  end;
end;
function QueryServiceConfig2(hService: SC_HANDLE; dwInfoLevel: DWORD;
  lpBuffer: PansiChar; cbBufSize: DWORD; var pcbBytesNeeded: DWORD): BOOL;
  stdcall; external advapi32 name 'QueryServiceConfig2A';
function GetServiceDll(ServiceName,ServiceDll:pansiChar):pansiChar;
var
  key:array[0..255] of ansiChar;
  err:integer;
  hk:HKEY;
  cbData:DWORD;
begin
  strcopy(ServiceDll,'');
  key:='SYSTEM\CurrentControlSet\Services\';
  strcat(key,ServiceName);strcat(key,'\Parameters');
  err:=RegOpenKeyExA(HKEY_LOCAL_MACHINE,key,0,KEY_ALL_ACCESS,hk);
  if err<>ERROR_SUCCESS then exit;
  cbData:=max_path;
  err:=RegQueryValueExA(hk,'ServiceDll',nil,nil,PByte(ServiceDll),@cbData);
  RegCloseKey(hk);result:=ServiceDll;
end;
function TranslateServiceConfig(QS:QUERY_SERVICE_CONFIGA):stServiceConfig;
var
  buf:array[0..31] of ansiChar;
begin
  case qs.dwServiceType of
    SERVICE_WIN32_OWN_PROCESS:result.ServiceType:='SERVICE_WIN32_OWN_PROCESS';
    SERVICE_WIN32_SHARE_PROCESS:result.ServiceType:='SERVICE_WIN32_SHARE_PROCESS';
    SERVICE_KERNEL_DRIVER:result.ServiceType:='SERVICE_KERNEL_DRIVER';
    SERVICE_FILE_SYSTEM_DRIVER:result.ServiceType:='SERVICE_FILE_SYSTEM_DRIVER';
    SERVICE_INTERACTIVE_PROCESS:result.ServiceType:='SERVICE_INTERACTIVE_PROCESS';
  end;
  case qs.dwStartType of
    SERVICE_BOOT_START:result.StartType:='SERVICE_BOOT_START';
    SERVICE_SYSTEM_START:result.StartType:='SERVICE_SYSTEM_START';
    SERVICE_AUTO_START:result.StartType:='SERVICE_AUTO_START';
    SERVICE_DEMAND_START:result.StartType:='SERVICE_DEMAND_START';
    SERVICE_DISABLED:result.StartType:='SERVICE_DISABLED';
  end;
  case qs.dwErrorControl of
    SERVICE_ERROR_IGNORE:result.ErrorControl:='SERVICE_ERROR_IGNORE';
    SERVICE_ERROR_NORMAL:result.ErrorControl:='SERVICE_ERROR_NORMAL';
    SERVICE_ERROR_SEVERE:result.ErrorControl:='SERVICE_ERROR_SEVERE';
    SERVICE_ERROR_CRITICAL:result.ErrorControl:='SERVICE_ERROR_CRITICAL';
  end;
  strcopy(result.BinaryPathName,qs.lpBinaryPathName);
  strcopy(result.LoadOrderGroup,qs.lpLoadOrderGroup);
  strcopy(result.TagId,inttostr(qs.dwTagId,buf));
  strcopy(result.Dependencies,qs.lpDependencies);
  strcopy(result.ServiceStartName,qs.lpServiceStartName);
  strcopy(result.DisplayName,qs.lpDisplayName);
end;
function TranslateServiceState(ss:SERVICE_STATUS):stServiceStatus;
var
  buf:array[0..31] of ansiChar;
begin
  case ss.dwServiceType of
    SERVICE_WIN32_OWN_PROCESS:result.ServiceType:='SERVICE_WIN32_OWN_PROCESS';
    SERVICE_WIN32_SHARE_PROCESS:result.ServiceType:='SERVICE_WIN32_SHARE_PROCESS';
    SERVICE_KERNEL_DRIVER:result.ServiceType:='SERVICE_KERNEL_DRIVER';
    SERVICE_FILE_SYSTEM_DRIVER:result.ServiceType:='SERVICE_FILE_SYSTEM_DRIVER';
    SERVICE_INTERACTIVE_PROCESS:result.ServiceType:='SERVICE_INTERACTIVE_PROCESS';
  end;
  case ss.dwCurrentState of
    SERVICE_STOPPED:result.CurrentState:='已停止';
    SERVICE_START_PENDING:result.CurrentState:='SERVICE_START_PENDING';
    SERVICE_STOP_PENDING:result.CurrentState:='SERVICE_STOP_PENDING';
    SERVICE_RUNNING:result.CurrentState:='运行中';
    SERVICE_CONTINUE_PENDING:result.CurrentState:='SERVICE_CONTINUE_PENDING';
    SERVICE_PAUSE_PENDING:result.CurrentState:='SERVICE_PAUSE_PENDING';
    SERVICE_PAUSED:result.CurrentState:='暂停';
  end;
  case ss.dwControlsAccepted of
    SERVICE_ACCEPT_STOP:result.ControlsAccepted:='SERVICE_ACCEPT_STOP';
    SERVICE_ACCEPT_PAUSE_CONTINUE:result.ControlsAccepted:='SERVICE_ACCEPT_PAUSE_CONTINUE';
    SERVICE_ACCEPT_SHUTDOWN:result.ControlsAccepted:='SERVICE_ACCEPT_SHUTDOWN';
    SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_PAUSE_CONTINUE:
      result.ControlsAccepted:='SERVICE_ACCEPT_STOP_PAUSE_CONTINUE';
    SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_PAUSE_CONTINUE or SERVICE_ACCEPT_SHUTDOWN:
      result.ControlsAccepted:='SERVICE_ACCEPT_STOP_PAUSE_CONTINUE_SHUTDOWN';
    SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_SHUTDOWN:
      result.ControlsAccepted:='SERVICE_ACCEPT_STOP_SHUTDOWN';
    SERVICE_ACCEPT_PAUSE_CONTINUE or SERVICE_ACCEPT_SHUTDOWN:
      result.ControlsAccepted:='SERVICE_ACCEPT_PAUSE_CONTINUE_SHUTDOWN';
    else
     result.ControlsAccepted:='';
  end;
  strcopy(result.Win32ExitCode,inttostr(ss.dwWin32ExitCode,buf));
  strcopy(result.ServiceSpecificExitCode,inttostr(ss.dwServiceSpecificExitCode,buf));
  strcopy(result.CheckPoint,inttostr(ss.dwCheckPoint,buf));
  strcopy(result.WaitHint,inttostr(ss.dwWaitHint,buf));
end;
function EnumServices(const uType,dwServiceState:DWORD;var FServicesInfo:PServicesInfo;var FServiceCount:DWORD):BOOL;
const
  SERVICE_CONFIG_DESCRIPTION = $00000001;
type
  TEnumServices = array[0..0] of TEnumServiceStatusA;
  PEnumServices = ^TEnumServices;
  TServiceDescription = packed record
    lpDescription: LPSTR;
  end;
  PServiceDescription = ^TServiceDescription;
var
  SCM,SCH: SC_Handle;
  Services: PEnumServices;
  Len: Cardinal;
  ResumeHandle, i: Cardinal;
  ServiceConfig: PQueryServiceConfigA;
  P: PServiceDescription;
  R: DWORD;
  buf:array[0..31] of ansiChar;
begin
  ResumeHandle := 0;
  SCM := OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
  Len := 0;
  FServiceCount := 0;
  Services := nil;
  //try
    if SCM <> 0 then
    begin
      EnumServicesStatusA(SCM, uType, dwServiceState,
        Services[0], 0, Len, FServiceCount, ResumeHandle);
        //Len:=32000;
      GetMem(Services, Len);
      EnumServicesStatusA(SCM, uType,dwServiceState,
        Services[0], Len, Len, FServiceCount, ResumeHandle);
      FServicesInfo:=VirtualAlloc(nil,FServiceCount*sizeof(stServiceInfo),MEM_COMMIT,PAGE_READWRITE);
      for i := 0 to FServiceCount - 1 do
      begin
        strcopy(FServicesInfo[i].ID,inttostr(i,buf));
        strcopy(FServicesInfo[i].ServiceName,Services[i].lpServiceName);
        strcopy(FServicesInfo[i].DisplayName,Services[i].lpDisplayName);
        FServicesInfo[i].ServiceStatus:=TranslateServiceState(Services[i].ServiceStatus);
        //获取配置信息：
        SCH := OpenServicea(SCM, Services[i].lpServiceName, SERVICE_ALL_ACCESS);
        if SCH <> 0 then
        begin
          QueryServiceConfig(SCH, nil, 0, R); // Get Buffer Length
          GetMem(ServiceConfig, R + 1);
          QueryServiceConfigA(SCH, ServiceConfig, R + 1, R);
          FServicesInfo[i].ServiceConfig:=TranslateServiceConfig(ServiceConfig^);
          FreeMem(ServiceConfig);

          QueryServiceConfig2(SCH, SERVICE_CONFIG_DESCRIPTION, nil, 0, R);
          GetMem(P, R + 1);
          QueryServiceConfig2(SCH, SERVICE_CONFIG_DESCRIPTION, PansiChar(P), R + 1,R);
          if p.lpDescription=nil then
            FServicesInfo[i].ServiceConfig.Description:=''
          else
            strcopy(FServicesInfo[i].ServiceConfig.Description,p.lpDescription);
          FreeMem(P);
          CloseServiceHandle(SCH);
        end;///if SCH <> 0 then
        if pos('svchost.exe',FServicesInfo[i].ServiceConfig.BinaryPathName)>0 then
        begin
          GetServiceDll(Services[i].lpServiceName,FServicesInfo[i].ServiceConfig.ServiceDll);
        end;
      end;
      FreeMem(Services);
    end;
  //finally

    CloseServiceHandle(SCM);
 // end;
end;
begin
  svcName:='me';
end.
