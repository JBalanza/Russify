import argparse
import sys
from functions import check_max_secret_length, hide, extract, check_secret_length
from pastebin import upload, download

headers = {
    "user-agent": "curl/7.74.0",
    "content-type": "application/x-www-form-urlencoded"
}

# For test
lorem_ipsum = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."


def check_message_file_and_secret(secret, message_file):
    if message_file is None:
        print("[-] As no message is provided, Lorem ipsum text will be used instead")
        # TODO maybe include a generator?
        n_lorems = int(check_secret_length(secret) / 22) + 1
        message = lorem_ipsum * n_lorems
    else:
        try:
            with open(message_file, 'r') as f:
                lines = f.readlines()
                message = ''.join(lines)
                print("[+] Message obtained from", message_file, "with a len of", len(message))
        except PermissionError as e:
            print("[-] The message couldn't be read from", message_file)
            print("[-] Lorem ipsum will be used instead. The maximum capacity of lorem is only 22 chars")
            message = lorem_ipsum
    return message


def main(args):
    parser = argparse.ArgumentParser(
        description='Stego tool to hide secrets in messages using homographic chars from cyrillic dictionaries. Texts '
                    'with hidden messages are uploaded to pastebin directly but downloaded through google translator')
    parser.add_argument('mode', choices=["upload", "download", "hide", "extract"], nargs='?', help='''
        upload/downloads uses pastebin to store the message and google translates API to download. 
        This might bypass some security boundaries at downloading hide/extract modes uses local files to store the secret
        ''')
    parser.add_argument("-dk", "--dev-key", dest="dev_key", help="Dev key used when uploading to pastebin")
    # parser.add_argument("-uk", "--user-key", dest="user_key", help="User key used when uploading to pastebin")
    parser.add_argument('-m', '--message_file', dest='message_file',
                        help='path to a test file containing a message to use as medium. If not provided, Lorem ipsum '
                             'will be used')
    parser.add_argument('-s', '--secret', dest='secret', help='The secret text that will be embedded')
    parser.add_argument('-d', '--destination_file', dest='destination_file',
                        help="destination file where the stego message will be stored")
    parser.add_argument('-o', '--stego_message_file', dest='stego_file',
                        help="Path to a file containing a stego message")
    parser.add_argument('-u', '--pastebin_url', dest='pastebin_url',
                        help='Pastebin url used in download to retrieve the secret from')
    parser.add_argument('-k', '--key', dest='key', help='They key used to encrypt and the crypt the secret.')
    args = parser.parse_args()

    if args.mode == "upload":
        if args.secret is None or args.dev_key is None:
            print("[-] In upload mode the following arguments are required")
            print("[-] -s <secret>")
            print("[-] -dk <dev_pastebin_key>")
            print("[-] -uv <user_pastebin_key")
            print("[-] -k <key>")
            sys.exit(1)
        message = check_message_file_and_secret(args.secret, args.message_file)
        max_len = check_max_secret_length(message)
        print("[+] Message maximum possible secret len:", max_len)
        print("[+] Secret length:", len(args.secret))
        message_stego = hide(message, args.secret, args.key)
        if message_stego is None:
            print("[-] The secret cannot be embedded within the message. Exiting...")
            exit(1)
        else:
            url = upload(message_stego, args.dev_key)
            print("[+] The message with the secret has been uploaded to:", url)
            exit(0)

    elif args.mode == "download":
        if args.pastebin_url is None and args.key is None:
            print("[-] Some of the options have not been provided")
            print("[-] Use the -u argument and provide the url returned in upload stage")
            print("[-] Use: -k <key>")
            exit(1)
        print("[+] Downloading the text from", args.pastebin_url)
        message_stego = download(args.pastebin_url)
        secret = extract(message_stego, args.key)
        print("[+] The secret is showed below:")
        print("----------------")
        print(secret)
        print("----------------")
        exit(0)

    elif args.mode == "hide":
        if args.secret is None or args.destination_file is None or args.key is None:
            print("[-] In hide mode the following arguments are required")
            print("[-] -s <secret>")
            print("[-] -d <path_to_destination_file>")
            print("[-] -k <key>")
            exit(1)
        message = check_message_file_and_secret(args.secret, args.message_file)
        max_len = check_max_secret_length(message)
        print("[+] Message maximum possible secret len:", max_len)
        print("[+] Secret length:", len(args.secret))
        message_stego = hide(message, args.secret, args.key)
        try:
            with open(args.destination_file, 'w', encoding='utf-8') as f:
                f.write(message_stego)
            print("[+] Message correctly written to", args.destination_file)
            exit(0)
        except PermissionError as e:
            print("[-] The file couldn't be written due to", e)
            exit(1)

    elif args.mode == "extract":
        if args.stego_file is None or args.key is None:
            print("[-] A path to a file containing a stego message and the key is needed")
            print("[-] Use: -o <path>")
            print("[-] Use: -k <key>")
            exit(1)
        try:
            with open(args.stego_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                stego_text = ''.join(lines)
            secret = extract(stego_text, args.key)
            print("[+] The secret is showed below:")
            print("----------------")
            print(secret)
            print("----------------")
            exit(0)
        except Exception as e:
            print("[-] The file couldn't be read due to", e)
            exit(1)
    else:
        parser.print_help()


if __name__ == '__main__':
    main(sys.argv)
    # print(get_pastebin_user_key(dev_key, "user", "pass"))
