{===============================================================================
TQQWry
 Class with QQWry.DAT - by ��� (coldwind@citiz.net)

   Status:  Freeware
 Compiler:  Delphi4, Delphi5, Delphi6, Delphi7
  Version:  1.0
 Lastdate:  19 March 2005
      Url:  http://51tec.vicp.net/

 �����ڴ�unit�У�ʵ���˶��ڴ�������(www.cz88.net)��IP���ݿ�Ķ�ȡ�������ݿ�����
 �Ѳ��Ļ�����ʵ�ֵģ��ֹ㷺Ӧ����QQ�͸�����̳�ϣ���ҪĿ���ǻ�ȡIP��ַ����������
 �Ķ�Ӧ��ϵ��
 ������unit�У��������е��������û�н���У�飬���������������ǰȷ����������
 ���⣬�������ʹ�ã��ڱ�unit�н�������ϸ��ע�⣬Ҳ�����̽�����һ��˵����
 ��������IP�����������������ͨ�����ַ����в��ҡ�

--------------------------------------------------------------------------------
===============================================================================}

unit untQQWry;

interface

uses
  SysUtils, Classes, Controls, Math, Dialogs;

type
  TQQWry = class(TObject)
    public
      constructor Create(cQQWryFileName: string);
      destructor Destroy; override;
      function GetQQWryFileName: string;
      function GetQQWryFileSize: Cardinal;
      function GetIPRecordNum: Cardinal;
      function GetQQWryDate: TDate;
      function GetQQWryDataFrom: string;
      function GetIPLocation(IPLocationOffset: Cardinal): TStringlist;
      function GetIPMsg(IPRecordID: Cardinal): TStringlist;
      function GetIPRecordID(IP: string): Cardinal;
      function GetIPValue(IP: string): Cardinal;
    private
      QQWryFileName: string;
      QQWryFileStream: TFileStream;
      QQWryFileSize: Cardinal;
      IPRecordNum: Cardinal;
      FirstIPIndexOffset, LastIPIndexOffset: Cardinal;
  end;

implementation

///**
//* ����һ��TQQWry��QQIP��ַ���ݿ�Ķ���
//* @param cQQWryFileName QQIP���ݿ��ļ���ȫ��������·��������ȷ���ļ����ںͿɶ���
//* @return ��
//*/
constructor TQQWry.Create(cQQWryFileName: string);
begin
  inherited Create;
  QQWryFileName:=cQQWryFileName;
  QQWryFileStream:=TFileStream.Create(QQWryFileName, fmOpenRead or fmShareDenyWrite, 0);
  QQWryFileSize:=QQWryFileStream.Size;
  QQWryFileStream.Read(FirstIPIndexOffset, 4);
  QQWryFileStream.Read(LastIPIndexOffset, 4);
  IPRecordNum:=(LastIPIndexOffset - FirstIPIndexOffset) div 7 + 1;
end;

///**
//* �����������ͷ�TQQWry�����ͷ��ļ�����������
//* @param  ��
//* @return ��
//*/
destructor TQQWry.Destroy;
begin
  QQWryFileStream.Free;
  inherited Destroy;
end;

///**
//* ��ȡQQIP���ݿ��ļ���ȫ��������·����
//* @param  ��
//* @return QQIP���ݿ��ļ���ȫ��������·����  string
//*/
function TQQWry.GetQQWryFileName: string;
begin
  Result:=QQWryFileName;
end;

///**
//* ��ȡQQIP���ݿ��ļ���С
//* @param  ��
//* @return QQIP���ݿ��ļ���С  Cardinal
//*/
function TQQWry.GetQQWryFileSize: Cardinal;
begin
  Result:=QQWryFileSize;
end;

///**
//* ��ȡQQIP���ݿ��ں��е�IP��ַ��Ϣ��¼����
//* @param  ��
//* @return QQIP���ݿ��ļ���С  Cardinal
//*/
function TQQWry.GetIPRecordNum: Cardinal;
begin
  Result:=IPRecordNum;
end;

///**
//* ��ȡ��ǰQQIP���ݿ�ĸ�������
//* @param  ��
//* @return QQIP��ǰ���ݿ�ĸ�������  TDate
//*/
function TQQWry.GetQQWryDate: TDate;
var
  DateString: string;
begin
  DateString:=GetIPMsg(GetIPRecordNum)[3];
  DateString:=copy(DateString, 1, pos('IP����', DateString) - 1);
  DateString:=StringReplace(DateString, '��', '-', [rfReplaceAll, rfIgnoreCase]);
  DateString:=StringReplace(DateString, '��', '-', [rfReplaceAll, rfIgnoreCase]);
  DateString:=StringReplace(DateString, '��', '-', [rfReplaceAll, rfIgnoreCase]);
  Result:=StrToDate(DateString);
end;

///**
//* ��ȡ��ǰQQIP���ݿ����Դ��Ϣ
//* @param  ��
//* @return ��ǰQQIP���ݿ����Դ��Ϣ  string
//*/
function TQQWry.GetQQWryDataFrom: string;
begin
  Result:=GetIPMsg(GetIPRecordNum)[2];
end;

///**
//* ����һ��IP���ҵ�����¼��ƫ�ƣ����ظ�IP��ַ����Ϣ
//* @param  IPLocationOffset  ���Ҽ�¼��ƫ��  Cardinal
//* @return IP��ַ��Ϣ��������Ϣ/������Ϣ)  string
//*/
function TQQWry.GetIPLocation(IPLocationOffset: Cardinal): TStringlist;
const
  //ʵ����Ϣ�ִ����λ�õ��ض���ģʽ
  REDIRECT_MODE_1 = 1;
  REDIRECT_MODE_2 = 2;
var
  RedirectMode: byte;
  CountryFirstOffset, CountrySecondOffset: Cardinal;
  CountryMsg, AreaMsg: string;
  ///**
  //* ����һ���ļ�ƫ��ֵ�������������ļ��и�ƫ���µ��ַ���������ȡ��0��β���ַ�ǰ
  //* @param  StringOffset  �ַ������ļ��е�ƫ��ֵ  Cardinal
  //* @return �ַ���  string
  //*/
  function ReadString(StringOffset: Cardinal): string;
  var
    ReadByte: char;
  begin
    Result:='';
    QQWryFileStream.Seek(StringOffset, soFromBeginning);
    QQWryFileStream.Read(ReadByte, 1);
    while ord(ReadByte)<>0 do begin
      Result := Result + ReadByte;
      QQWryFileStream.Read(ReadByte, 1);
    end;
  end;
  ///**
  //* ����һ��������Ϣƫ��ֵ�������������ļ��и�ƫ�����µĵ�����Ϣ
  //* @param  AreaOffset ������Ϣ���ļ��е�ƫ��ֵ  Cardinal;
  //* @return ������Ϣ�ַ���  string
  //*/
  function ReadArea(AreaOffset: Cardinal): string;
  var
    ModeByte: byte;
    ReadAreaOffset: Cardinal;
  begin
    QQWryFileStream.Seek(AreaOffset, soFromBeginning);
    QQWryFileStream.Read(ModeByte, 1);
    if (ModeByte = REDIRECT_MODE_1) or (ModeByte = REDIRECT_MODE_2) then begin
      QQWryFileStream.Read(ReadAreaOffset, 3);
      if ReadAreaOffset=0 then Result:='δ֪����'
      else Result:=ReadString(ReadAreaOffset);
    end else begin
      Result:=ReadString(AreaOffset);
    end;
  end;
begin
  //����4���ֽڣ���4�ֽ�����Ϊ����IP��Ϣ��IP��ַ���е���ֹIPֵ
  QQWryFileStream.Seek(IPLocationOffset + 4, soFromBeginning);
  //��ȡ������Ϣ���ض���ģʽֵ
  QQWryFileStream.Read(RedirectMode, 1);

  //�ض���ģʽ1�Ĵ���
  if RedirectMode = REDIRECT_MODE_1 then begin
    //ģʽֵΪ1�����3���ֽڵ�����Ϊ������Ϣ���ض���ƫ��ֵ
    QQWryFileStream.Read(CountryFirstOffset, 3);
    //�����ض���
    QQWryFileStream.Seek(CountryFirstOffset, soFromBeginning);
    //�ڶ��ζ�ȡ������Ϣ���ض���ģʽ
    QQWryFileStream.Read(RedirectMode, 1);
    //�ڶ����ض���ģʽΪģʽ2�Ĵ���
    if RedirectMode = REDIRECT_MODE_2 then begin
      //��3�ֽڵ����ݼ�Ϊ�ڶ����ض���ƫ��ֵ
      QQWryFileStream.Read(CountrySecondOffset, 3);
      //��ȡ�ڶ����ض���ƫ��ֵ�µ��ַ���ֵ����Ϊ������Ϣ
      CountryMsg:=ReadString(CountrySecondOffset);
      //����һ���ض���ģʽΪ1�������ض�����ȡ�ĵڶ����ض���ģʽΪ2��
      //�������Ϣ����ڵ�һ�ι�����Ϣƫ��ֵ�ĺ���
      QQWryFileStream.Seek(CountryFirstOffset + 4, soFromBeginning);
    //�ڶ����ض���ģʽ����ģʽ2�Ĵ���
    end else begin
      CountryMsg:=ReadString(CountryFirstOffset);
    end;
    //���ض���ģʽ1�¶�������Ϣֵ
    AreaMsg:=ReadArea(QQWryFileStream.Position);
  //�ض���ģʽ2�Ĵ���
  end else if RedirectMode = REDIRECT_MODE_2 then begin
    QQWryFileStream.Read(CountrySecondOffset, 3);
    CountryMsg:=ReadString(CountrySecondOffset);
    AreaMsg:=ReadArea(IPLocationOffset + 8);
  //�����ض���ģʽ�Ĵ�������ŵļ���IP��ַ��Ϣ
  end else begin
    CountryMsg:=ReadString(QQWryFileStream.Position - 1);
    AreaMsg:=ReadArea(QQWryFileStream.Position);
  end;
  Result:=TStringlist.Create;
  Result.Add(CountryMsg);
  Result.Add(AreaMsg);
end;

///**
//* ����һ��IP��ַ��Ϣ��¼�ţ����ظ����¼����Ϣ
//* @param  IPRecordID  IP��ַ��Ϣ��¼��  Cardinal
//* @return ��¼����Ϣ����3�����֣�����ʼIP��ַ  ����ֹIP��ַ  �۹�����Ϣ/������Ϣ)  TStringlist
//*/
function TQQWry.GetIPMsg(IPRecordID: Cardinal): TStringlist;
var
  aryStartIP: array[1..4] of byte;
  strStartIP: string;

  EndIPOffset: Cardinal;
  aryEndIP: array[1..4] of byte;
  strEndIP: string;
  
  i: integer;
begin
  //���ݼ�¼ID���Ƶ��ü�¼�ŵ�������
  QQWryFileStream.Seek(FirstIPIndexOffset + (IPRecordID - 1) * 7, soFromBeginning);
  //������ǰ4���ֽ�Ϊ��ʼIP��ַ
  QQWryFileStream.Read(aryStartIP, 4);
  //��3���ֽ������������ƫ��ֵ
  QQWryFileStream.Read(EndIPOffset, 3);

  //������������
  QQWryFileStream.Seek(EndIPOffset, soFromBeginning);
  //���������ǰ4���ֽ�Ϊ��ֹIP��ַ
  QQWryFileStream.Read(aryEndIP, 4);

  //����ֹIP��ַת��Ϊ��ֵ���ʽ
  strStartIP:='';
  for i:=4 downto 1 do begin
    if i<>1 then strStartIP:=strStartIP + IntToStr(aryStartIP[i]) + '.'
    else strStartIP:=strStartIP + IntToStr(aryStartIP[i]);
  end;

  strEndIP:='';
  for i:=4 downto 1 do begin
    if i<>1 then strEndIP:=strEndIP + IntToStr(aryEndIP[i]) + '.'
    else strEndIP:=strEndIP + IntToStr(aryEndIP[i]);
  end;

  Result:=TStringlist.Create;
  Result.Add(strStartIP);
  Result.Add(strEndIP);
  //��ȡ������¼�µ�IP��ַ��Ϣ
  //����������ͳһ�ģ������������ƫ��ֵ  ����ֹIP��ַ�Ĵ��λ��  �۹�����Ϣ��������ֹIP��ַ���λ�ú�
  Result.AddStrings(GetIPLocation(EndIPOffset));
end;

///**
//* ����һ��IP��ַ���Ķε���ַ�����ʽ�������ظ�IP����ֵ
//* @param  IP  IP��ַ���Ķε���ַ�����ʽ��  string
//* @return ��IP����ֵ  Cardinal
//*/
function TQQWry.GetIPValue(IP: string): Cardinal;
var
  tsIP: TStringlist;
  i: integer;
  function SplitStringToStringlist(aString: string; aSplitChar: string): TStringlist;
  begin
    Result:=TStringList.Create;
    while pos(aSplitChar, aString)>0 do begin
      Result.Add(copy(aString, 1, pos(aSplitChar, aString)-1));
      aString:=copy(aString, pos(aSplitChar, aString)+1, length(aString)-pos(aSplitChar, aString));
    end;
    Result.Add(aString);
  end;
begin
  tsIP:=SplitStringToStringlist(IP, '.');
  Result:=0;
  for i:=3 downto 0 do begin
    Result:=Result + StrToInt(tsIP[i]) * trunc(power(256, 3-i));
  end;
end;

///**
//* ����һ��IP��ַ���Ķε���ַ�����ʽ�������ظ�IP��ַ���ڵļ�¼��
//* @param  IP  IP��ַ���Ķε���ַ�����ʽ��  string
//* @return ��IP��ַ���ڵļ�¼��  Cardinal
//*/
function TQQWry.GetIPRecordID(IP: string): Cardinal;
  function SearchIPRecordID(IPRecordFrom, IPRecordTo, IPValue: Cardinal): Cardinal;
  var
    CompareIPValue1, CompareIPValue2: Cardinal;
  begin
    Result:=0;
    QQWryFileStream.Seek(FirstIPIndexOffset + ((IPRecordTo - IPRecordFrom) div 2 + IPRecordFrom - 1) * 7, soFromBeginning);
    QQWryFileStream.Read(CompareIPValue1, 4);
    QQWryFileStream.Seek(FirstIPIndexOffset + ((IPRecordTo - IPRecordFrom) div 2 + IPRecordFrom) * 7, soFromBeginning);
    QQWryFileStream.Read(CompareIPValue2, 4);
    //�ҵ���
    if (IPValue>=CompareIPValue1) and (IPValue<CompareIPValue2) then begin
      Result:=(IPRecordTo - IPRecordFrom) div 2 + IPRecordFrom;
    end else
      //������
      if IPValue>CompareIPValue1 then begin
        Result:=SearchIPRecordID((IPRecordTo - IPRecordFrom) div 2 + IPRecordFrom + 1, IPRecordTo, IPValue);
      end else
        //ǰ�����
        if IPValue<CompareIPValue1 then begin
          Result:=SearchIPRecordID(IPRecordFrom, (IPRecordTo - IPRecordFrom) div 2 + IPRecordFrom - 1, IPValue);
        end;
  end;
begin
  Result:=SearchIPRecordID(1, GetIPRecordNum, GetIPValue(IP));      
end;

end.