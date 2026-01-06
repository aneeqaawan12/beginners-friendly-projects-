file = "expenses.txt"

def welcome():
    print("Welcome to the expenses tracker")
    print("-------------------------------")
    print("1. Add Expenses")
    print("2. View Expenses")
    print("3. Total Expenses")
    print("4. Remove Expenses")
    print("5. Exit")
    print("-------------------------------")
    print()

welcome()

def load_expenses():
    expenses = []

    try:
        with open(file, "r") as f:
            for line in f:
                category, amount = line.strip().split(",")
                expenses.append({"category": category, "amount": float(amount)})
    except FileNotFoundError:
        print("File doesn't exist! ")
    except Exception as e:
        print(e)
    return expenses
    

def save_expenses(expenses):
    with open(file, "w") as f:
        for e in expenses:
            f.write(f"{e["category"]},{e["amount"]}")


def add_expenses(expenses):
    try:
        category = input("Enter your category: ")
        amount = float(input("Enter your amount: ")) 
        expenses.append({"category":category, "amount": amount}) 
        save_expenses(expenses)
        print("Expenses added Successfully! ")
    except ValueError:
        print("Invalid amount input ! ")

    except Exception as e:
        print(e)

def view_expenses(expenses):
    if not expenses:
        print("\nThere are no expenses to view.")
        return
    print("\nExpenses: ")
    i = 1
    for e in expenses:
        print(f"{i}. {e["category"]} = {e["amount"]}$")
        i += 1
    print()

def total_expenses(expenses):
    total = 0
    for e in expenses:
        total += e["amount"]
    
    print(f"Your Total expenditure is : {total}$")

def remove_expenses(expenses):
    if not expenses:
        print("\nThere are no expenses to remove.")
        return
    view_expenses(expenses)
    try:
        number = int(input("Enter your Expense number to delete: "))
        if number>=1 and number <= len(expenses):
            removed = expenses.pop(number - 1)
            save_expenses(expenses)
            print(f"{removed["category"]} - {removed["amount"]}")
        else:
            print("invalid number\n")

    except ValueError:
        print("Enter a valid number. \n")

def main():
    welcome()
    expenses = load_expenses()
    while True:
        choice = input("Choose number: ")
        if choice == '1':
            add_expenses(expenses)
        elif choice == '2':
            view_expenses(expenses)
        elif choice == '3':
            total_expenses(expenses)
        elif choice == '4':
            remove_expenses(expenses)
        elif choice == '5':
            print("Thank you for using Expense Tracker !")
            return
        else:
            print("Invalid input . try again")

main()