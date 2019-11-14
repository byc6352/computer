unit funcs;

interface
const
  user32    = 'user32.dll';
function wsprintf(Output: PansiChar; Format: PansiChar): Integer; stdcall;


function StrCopy(Dest: PansiChar; const Source: PansiChar): PansiChar;
function StrCat(Dest: PansiChar; const Source: PansiChar): PansiChar;
function StrEnd(const Str: PansiChar): PansiChar; assembler;
function StrRScan(const Str: PansiChar; Chr: ansiChar): PansiChar; assembler;
function StrLen(const Str: PansiChar): Cardinal; assembler;
function StrLCopy(Dest: PansiChar; const Source: PansiChar; MaxLen: Cardinal): PansiChar; assembler;
function StrPos(const Str1, Str2: PansiChar): PansiChar; assembler;
function _wsprintf(lpOut: PansiChar; lpFmt: PansiChar; lpVars: Array of Const):Integer; assembler;

function Inttostr(i:integer;str:pansiChar):pansiChar; assembler;
function ExtractFileDir(FileName,FileDir:pansiChar):pansiChar;
function ExtractFilename(str:pansiChar):pansiChar;
implementation
function wsprintf; external user32 name 'wsprintfA';

function _wsprintf(lpOut: PansiChar; lpFmt: PansiChar; lpVars: Array of Const):Integer; assembler;
var
  Count:integer;
  v1,v2:integer;
asm
  mov v1,eax
  mov v2,edx
  mov eax,ecx
  mov ecx,[ebp+$08]
  inc ecx
  mov Count,ecx
  dec ecx
  imul ecx,8
  add eax,ecx
  mov ecx,Count
  @@1:
  mov edx,[eax]
  push edx
  sub eax,8
  loop @@1
  push v2
  push v1
  Call wsprintf
  mov ecx,Count
  imul ecx,4
  add ecx,8
  add esp,ecx
end;
function StrPos(const Str1, Str2: PansiChar): PansiChar; assembler;
asm
        PUSH    EDI
        PUSH    ESI
        PUSH    EBX
        OR      EAX,EAX
        JE      @@2
        OR      EDX,EDX
        JE      @@2
        MOV     EBX,EAX
        MOV     EDI,EDX
        XOR     AL,AL
        MOV     ECX,0FFFFFFFFH
        REPNE   SCASB
        NOT     ECX
        DEC     ECX
        JE      @@2
        MOV     ESI,ECX
        MOV     EDI,EBX
        MOV     ECX,0FFFFFFFFH
        REPNE   SCASB
        NOT     ECX
        SUB     ECX,ESI
        JBE     @@2
        MOV     EDI,EBX
        LEA     EBX,[ESI-1]
@@1:    MOV     ESI,EDX
        LODSB
        REPNE   SCASB
        JNE     @@2
        MOV     EAX,ECX
        PUSH    EDI
        MOV     ECX,EBX
        REPE    CMPSB
        POP     EDI
        MOV     ECX,EAX
        JNE     @@1
        LEA     EAX,[EDI-1]
        JMP     @@3
@@2:    XOR     EAX,EAX
@@3:    POP     EBX
        POP     ESI
        POP     EDI
end;
function StrLen(const Str: PansiChar): Cardinal; assembler;
asm
        MOV     EDX,EDI
        MOV     EDI,EAX
        MOV     ECX,0FFFFFFFFH
        XOR     AL,AL
        REPNE   SCASB
        MOV     EAX,0FFFFFFFEH
        SUB     EAX,ECX
        MOV     EDI,EDX
end;
function StrLCopy(Dest: PansiChar; const Source: PansiChar; MaxLen: Cardinal): PansiChar; assembler;
asm
        PUSH    EDI
        PUSH    ESI
        PUSH    EBX
        MOV     ESI,EAX
        MOV     EDI,EDX
        MOV     EBX,ECX
        XOR     AL,AL
        TEST    ECX,ECX
        JZ      @@1
        REPNE   SCASB
        JNE     @@1
        INC     ECX
@@1:    SUB     EBX,ECX
        MOV     EDI,ESI
        MOV     ESI,EDX
        MOV     EDX,EDI
        MOV     ECX,EBX
        SHR     ECX,2
        REP     MOVSD
        MOV     ECX,EBX
        AND     ECX,3
        REP     MOVSB
        STOSB
        MOV     EAX,EDX
        POP     EBX
        POP     ESI
        POP     EDI
end;
function StrEnd(const Str: PansiChar): PansiChar; assembler;
asm
        MOV     EDX,EDI
        MOV     EDI,EAX
        MOV     ECX,0FFFFFFFFH
        XOR     AL,AL
        REPNE   SCASB
        LEA     EAX,[EDI-1]
        MOV     EDI,EDX
end;
function StrCat(Dest: PansiChar; const Source: PansiChar): PansiChar;
begin
  StrCopy(StrEnd(Dest), Source);
  Result := Dest;
end;
function StrCopy(Dest: PansiChar; const Source: PansiChar): PansiChar;
asm
        PUSH    EDI
        PUSH    ESI
        MOV     ESI,EAX
        MOV     EDI,EDX
        MOV     ECX,0FFFFFFFFH
        XOR     AL,AL
        REPNE   SCASB
        NOT     ECX
        MOV     EDI,ESI
        MOV     ESI,EDX
        MOV     EDX,ECX
        MOV     EAX,EDI
        SHR     ECX,2
        REP     MOVSD
        MOV     ECX,EDX
        AND     ECX,3
        REP     MOVSB
        POP     ESI
        POP     EDI
end;
function StrRScan(const Str: PansiChar; Chr: ansiChar): PansiChar; assembler;
asm
        PUSH    EDI
        MOV     EDI,Str
        MOV     ECX,0FFFFFFFFH
        XOR     AL,AL
        REPNE   SCASB
        NOT     ECX
        STD
        DEC     EDI
        MOV     AL,Chr
        REPNE   SCASB
        MOV     EAX,0
        JNE     @@1
        MOV     EAX,EDI
        INC     EAX
@@1:    CLD
        POP     EDI
end;

function Inttostr(i:integer;str:pansiChar):pansiChar;
begin
  _wsprintf(str,'%d',[i]);
  result:=str;
end;
function ExtractFileDir(FileName,FileDir:pansiChar):pansiChar;
var
  p:pansiChar;
begin
  result:=nil;
  p:=strRscan(FileName,'\');
  if p=nil then exit;
  strLcopy(FileDir,FileName,p-FileName);
  result:=FileDir;
end;
function ExtractFilename(str:pansiChar):pansiChar;
var
  i,j:integer;
  p:pansiChar;
begin
  j:=strlen(str);
  p:=str;
  for i:=j downto 0 do
  begin
    if str[i]='\' then
    begin
      p:=@str[i+1];
      break;
    end;//if
  end;//for
  result:=p;
end;
end.
