# PureArgon2Swift

A pure implementation of the Argon2 algorithm in Swift.

**Note:** For the Blake2b parts of the algorithm a C implementation of Blake2b is used.

## **Executable**
You can run PureArgon2Swift as executable in your terminal, by following these steps:

1. Make sure Xcode is installed. 

2. Make sure the Command Line Utilities are installed: `xcode-select --install`

3. Then run following:
```
git clone https://github.com/sp4c38/PureArgon2Swift.git
cd PureArgon2Swift
make
```

4. Now you've got the `argon2` executable file. To get the help message run `./argon2 -h`

	An example for testing:  
	`echo -n "Password" | ./argon2 Salt1234 -p 3 -k 2048 -t 1`

## **Library**
You can import PureArgon2Swift in your project using the Swift Package Manager.
- _Add in Package.swift:_

	Append following to your dependencies: `.package(url: "https://github.com/sp4c38/PureArgon2Swift", from: "1.0.0")`  
	Append following to your targets dependencies: `.product(name: "Argon2", package: "PureArgon2Swift")`

- _Add in Xcode project:_

	In the menu go to File > Add Packages... > in search bar type https://github.com/sp4c38/PureArgon2Swift > Add Package > Checkmark "Argon2" > Add Package

## Implementation notes

Based on Argon2 RFC 9106: https://www.rfc-editor.org/rfc/rfc9106.pdf. Inspired by https://github.com/bwesterb/argon2pure.
