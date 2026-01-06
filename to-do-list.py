#what to include
#add task --- use list to add task and store them
#view task  ---- for loop 
#mark complete the task
#remove task ---- append / remove

tasks = []

def welcome():
    print("Welcome to To - Do list")
    print("------------------------------")
    print("1. Add task")
    print("2. view tasks")
    print("3. Mark the task")
    print("4. Remove the task")
    print("------------------------------")
    print("5. Exit \n")

def add_task():
    choice = input("Enter your task: ")
    tasks.append(choice)
    print("Task added sccessfully!\n")

def view_task():
    i = 1
    for task in tasks:
        print(f"task {i}:  {task} ")
        i += 1

def mark_task():
    task_number = int(input("Enter you task number for marking : ")) -1
    if task_number >0 and task_number <= len(tasks):
        tasks[task_number] = f"{tasks[task_number]} - completed!"
        print("Task marked as completed!")
    else:
        print("Invalid task number \n")

def delete():
    task_number = int(input("Enter you task number for removing : "))
    if task_number >0 and task_number < len(tasks):
        tasks.remove(tasks[task_number])
        print("Task deleted successfully! \n")
    
    else:
        print("Invalid task number\n")


def main():
    welcome()
    while True:
        choice = input("\nEnter your choice: ")
        if choice == '1':
            add_task()
        elif choice == '2':
            view_task()
        elif choice == '3':
            mark_task()
        elif choice == '4':
            delete()
        elif choice == '5':
            print("Thank you for using the program!\n")
            return
        else:
            print("Invalid Input. Try again!\n")

main()