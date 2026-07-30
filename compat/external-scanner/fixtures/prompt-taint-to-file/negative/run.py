import os

user_input = input("Enter filename: ")
with open("/tmp/" + user_input, "w") as f:
    f.write("hello")
