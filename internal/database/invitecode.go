package database

type InviteCode struct {
	Id      uint64
	Creator uint64
	Code    string
}

func (ic *InviteCode) Use() error {
	err := GetDB().QueryRow("SELECT invite_code_id_ FROM invite_codes WHERE code_=$1 AND used_=false;",
		ic.Code).Scan(&ic.Id)
	if err != nil {
		return err
	}

	_, err = GetDB().Query("UPDATE invite_codes SET used_=true WHERE invite_code_id_=$1;", ic.Id)
	return err
}
