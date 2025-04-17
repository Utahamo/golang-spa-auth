package database

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

type User struct {
	ID       int    `json:"id" gorm:"primaryKey"`
	Email    string `json:"email" gorm:"unique;not null"`
	Username string `json:"username" gorm:"unique;not null"`
	Password string `json:"password" gorm:"not null"`
	TwoFA    string `json:"2fa"` // 2FA 密钥或代码
	// 其他字段可以根据需要添加
}

// InitDB 初始化数据库连接
func InitDB() error {
	var err error
	db, err = gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
	if err != nil {
		return err
	}

	// 自动迁移，创建用户表
	err = db.AutoMigrate(&User{})
	if err != nil {
		return err
	}

	return nil
}

func Getdb() *gorm.DB {
	return db
}
