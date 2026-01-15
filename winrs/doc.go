// Package winrs provides a Windows Remote Shell (WinRS) client.
//
// WinRS enables execution of cmd.exe commands on remote Windows systems
// via the WS-Management (WSMan) protocol. Unlike PSRP (PowerShell Remoting),
// WinRS executes native Windows commands without PowerShell overhead.
//
// Basic usage:
//
//	shell, err := winrs.NewShell(ctx, wsmanClient,
//	    winrs.WithWorkingDirectory("C:\\temp"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer shell.Close(ctx)
//
//	proc, err := shell.Run(ctx, "dir", "/b")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(string(proc.Stdout))
package winrs
