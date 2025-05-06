package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

var (
	InfoLogger  *log.Logger
	ErrorLogger *log.Logger
	DebugLogger *log.Logger
)

// Init 初始化日志记录器
func Init() {
	// 确保日志目录存在
	logDir := "logs"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		os.Mkdir(logDir, 0o755)
	}

	// 创建日志文件，使用当前日期作为文件名
	currentTime := time.Now().Format("2006-01-02")
	logFile := filepath.Join(logDir, fmt.Sprintf("client-%s.log", currentTime))

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		log.Fatal("无法打开日志文件:", err)
	}

	// 设置不同级别的日志记录器
	InfoLogger = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	DebugLogger = log.New(file, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)

	// 同时输出到控制台
	InfoLogger.SetOutput(os.Stdout)
	ErrorLogger.SetOutput(os.Stderr)

	InfoLogger.Println("日志系统初始化完成")
}

// Info 记录信息级别日志
func Info(format string, v ...interface{}) {
	if InfoLogger != nil {
		InfoLogger.Printf(format, v...)
	}
}

// Error 记录错误级别日志
func Error(format string, v ...interface{}) {
	if ErrorLogger != nil {
		ErrorLogger.Printf(format, v...)
	}
}

// Debug 记录调试级别日志
func Debug(format string, v ...interface{}) {
	if DebugLogger != nil {
		DebugLogger.Printf(format, v...)
	}
}
