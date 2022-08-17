package database

type Login struct {
	String string
}

func (login Login) Change(user_id uint64) error {
	_, err := GetDB().Query("UPDATE users SET login_=$1 WHERE user_id_=$2;",
		login.String, user_id)
	return err
}
