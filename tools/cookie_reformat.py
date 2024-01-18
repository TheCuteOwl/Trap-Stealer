file_path = input("Enter the cookie file path: ")
file_path = file_path.strip('"')
with open(file_path, 'r') as file:
    lines = file.readlines()
formatted_cookies = []
for line in lines:
    parts = line.split()
    if len(parts) == 3:
        domain, name, value = parts
        formatted_cookies.append(f"{domain}\tTRUE\t/\tFALSE\t0\t{name}\t{value}\n")
output_path = 'output_cookies.txt'
with open(output_path, 'w') as file:
    file.writelines(formatted_cookies)
input(f"Formatted cookies have been saved to {output_path}")
