# BSIT 3B Asis, Randiel James Z.
import os
import sys


# Main code
def add_email(email):
    if len(email) > 100:  # naga limit to 100 characters
        print("Email address exceeds the maximum length of 100 characters.")
        return

    # dito na code if may existing na maga sabi yan
    formatted_email = email.lower()
    with open("account.txt", "r+") as file:
        emails = file.read().split()
        if formatted_email in emails:
            print(f"{formatted_email} Account Already Exists!")
            return
        emails.append(formatted_email)
        file.seek(0)
        file.write("\n".join(emails))  # para iwas dikit dikit na email
        print(f"Adding: {formatted_email}")


# dito naman added feature lang removing ng account
def remove_email(email):
    with open("account.txt", "r+") as file:
        emails = file.read().split()
        if email not in emails:
            print(f"{email} Account Does Not Exist!")
            return
        emails.remove(email)
        file.seek(0)
        file.write("\n".join(emails))


# dito naman yung file functions
def view_emails():
    with open("account.txt", "r") as file:
        emails = file.read()
        print(emails)


def main():
    # kung wala pang existing file gagawa ng new file
    if not os.path.exists("account.txt"):
        with open("account.txt", "w"):
            pass

    # mga commands
    if len(sys.argv) != 3:
        print("Usage: python manage.py [-a/-x] email")
        return

    command = sys.argv[1]
    email = sys.argv[2]

    if command == "-a":
        add_email(email)
    elif command == "-x":
        remove_email(email)
    else:
        print("Invalid command!")


if __name__ == "__main__":
    main()
