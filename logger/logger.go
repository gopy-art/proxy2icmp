package logger

import (
	"io"
	"log"
	"os"
)

var (
	InfoLogger  *log.Logger
	ErrorLogger *log.Logger
)

func InitLogger(enableflage int) {
	var wrt io.Writer
	if enableflage==0{
		wrt = io.MultiWriter(os.Stdout)
	}else if enableflage==1{
		file, err := os.OpenFile("./proxy2icmp.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
		}
		wrt = io.MultiWriter(file)
	}else if enableflage==2{
		wrt = io.MultiWriter(io.Discard)
	}
	InfoLogger = log.New(wrt, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLogger = log.New(wrt, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	InfoLogger.SetOutput(wrt)
	ErrorLogger.SetOutput(wrt)
}
