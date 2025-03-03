## How to use


### Quick start

Overall(Ignore the server side):

1. Go to [release](https://github.com/acking-you/proxy-everything/releases) to download the corresponding `http-proxy-cli` command-line tool (the suffix corresponds to different platforms).  
2. Use the command `http-proxy-cli -s <proxy-server-ip> -c <local-port>` to start the proxy service locally, which will run on `<local-port>` (similar to Clash's default port 7890).  
3. Direct the applications that need proxying to use the local proxy service. For instance, you can set the HTTP traffic proxy at the operating system level (this will proxy most traffic from applications based on the HTTP protocol, with browsers being a typical example).  
4. Now, happily open YouTube and start your browsing journey!


#### Windows
1.  Download `http-proxy-cli.exe` from [this link](https://github.com/acking-you/proxy-everything/releases/download/0.1.7/http-proxy-cli-0.1.7-x86_64-pc-windows-msvc.zip).

2.  Open Command Prompt (cmd) and ensure that `http-proxy-cli.exe` is located in the current directory. Execute the following command to start the proxy (note that `lb7666.top` is the author's mapped domain; you should replace this with your own machine's address, and `11111` is the author's preferred local port, but you can change it to something like `7890` if you prefer):

    ```sh
    .\http-proxy-cli.exe -s lb7666.top -c 11111
    ```

3.  As shown in the images below, locate and enable system-wide proxy settings, entering the port number specified in the second step.

    ![img1](./assets/win-proxy1.png)
    ![img2](./assets/win-proxy2.png)

4.  Launch your browser and navigate to Google – enjoy unrestricted access!

5.  For ease of use, it's recommended to save the command from step 2 as a `start_proxy.bat` file. You can then simply double-click this file in the appropriate directory to start the proxy each time. However, remember to always complete step 3 as well.

#### Linux


#### MacOS


#### Android



#### IOS