package optsmb

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/pkg/smb"
)

const HelpMsg = `
shares - list available shares
use {sharename} - connect to an specific share
cd {path} - changes the current directory to {path}
ls {opt path} - lists all the files in the current directory or the specified path
tree {filepath} - recursively lists all files in folder and sub folders
rm {file} - removes the selected file
mkdir {dirname} - creates the directory under the current path
rmdir {dirname} - removes the directory under the current path
put {filename} - uploads the filename into the current path
get {filename} - downloads the filename from the current path
mget {mask} - downloads all files from the current directory matching the provided mask
cat {filename} - reads the filename from the current path
mount {target,path} - creates a mount point from {path} to {target} (admin required)
umount {path} - removes the mount point at {path} without deleting the directory (admin required)
close - closes the current SMB Session
exit - terminates the server process (and this session)
logoff - logs off

`

func (o *Options) smbclient(target string) {
	prt := printer.NewPrinter("SMB", target, o.target2SMBInfo[target].NetBIOSComputerName, 445)

	s, creds, err := o.authenticate(target, DefaultPort, true)
	if err != nil {
		prt.PrintFailure(err.Error())
		return
	}
	defer func() {
		_ = s.Logoff()
	}()

	var stop bool = false
	var currentShare *smb.Share
	baseLoc := fmt.Sprintf("\\\\%s\\", target)
	cwd := "."
	share := ""
	cmdBufio := bufio.NewReader(os.Stdin)
	for !stop {
		fmt.Printf("(%s) %s >> ", creds.Username, baseLoc+share+cwd)
		cmd, err := cmdBufio.ReadString('\n')
		if err != nil {
			prt.StoreFailure(err.Error())
			return
		}

		cmd = strings.ReplaceAll(strings.ReplaceAll(cmd, "\n", ""), "\r", "")
		switch cmd {
		case "exit", "logoff", "close":
			stop = true
		case "help":
			fmt.Print(HelpMsg)
			continue
		case "shares":
			sharenames, err := s.ListSharenames()
			if err != nil {
				fmt.Println("ERR:", err)
			} else {
				for _, s := range sharenames {
					fmt.Println(s)
				}
			}
			continue
		case "ls":
			cmd = "ls " + cwd
		case "cd":
			cwd = "."
			continue
		}

		splitted := strings.Split(cmd, " ")
		if len(splitted) != 2 {
			fmt.Printf("Unknown command: '%s'\n", cmd)
			continue
		}

		switch splitted[0] {
		case "use":
			if currentShare != nil {
				fmt.Println("Unmounting current share")
				_ = currentShare.Umount()
				share = ""
			}
			currentShare, err = s.Mount(splitted[1])
			if err != nil {
				fmt.Println("ERR:", err)
			} else {
				share = splitted[1] + "\\"
			}
		case "ls":
			if currentShare == nil {
				fmt.Println("No share is mounted")
				continue
			}
			_ = fs.WalkDir(currentShare.DirFS(cwd), splitted[1], func(path string, d fs.DirEntry, err error) error {
				if strings.Count(path, "/") != 0 {
					if d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				fmt.Println(path)
				return nil
			})
		case "cd":
			if currentShare == nil {
				fmt.Println("No share is mounted")
				continue
			}
			cwd = splitted[1]
		}
	}
	prt.PrintInfo("session closed")
}
