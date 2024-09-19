# kc-toolkit

kc-toolkit is a command line interface for adding, removing, modifying . . . users, domain-password pairs . . .

The purpose of this tool is to easily develop [keeper-crabby](https://github.com/TelurijevDioksid/keeper-crabby).
Use 'help' command for more information.

## Usage

```console
test@test:/$ kc_toolkit.exe help
Usage:
    kc_toolkit [command] [options]

Commands:
    create          Create a new user
        -u, --username  Username (default: user)
        -m, --master    Master password (default: master)
        -d, --domain    Domain (default: domain)
        -p, --password  Password (default: password)

    delete          Delete a user
        -u, --username  Username (required)

    check           Check if a user exists
        -u, --username  Username (required)

    read            Read a user
        -u, --username  Username (required)
        -m, --master    Master password (required)

    add-pwd         Add a password to a user
        -u, --username  Username (required)
        -m, --master    Master password (required)
        -d, --domain    Domain (required)
        -p, --password  Password (required)

    delete-pwd      Delete a password from a user
        -u, --username  Username (required)
        -m, --master    Master password (required)
        -d, --domain    Domain (required)

    modify-pwd     Modify a password from a user
        -u, --username  Username (required)
        -m, --master    Master password (required)
        -d, --domain    Domain (required)
        -p, --password  Password (required)

    clear           Clear all users

    help            Display this message
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
