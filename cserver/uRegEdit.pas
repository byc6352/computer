unit uRegEdit;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ExtCtrls, Buttons;

type
  TFRegEdit = class(TForm)
    edtValName: TLabeledEdit;
    edtValData: TLabeledEdit;
    btnOK: TBitBtn;
    btnCancel: TBitBtn;
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  FRegEdit: TFRegEdit;

implementation

{$R *.dfm}

end.
