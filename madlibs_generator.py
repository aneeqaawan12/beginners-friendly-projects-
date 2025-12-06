with open("story.txt", "r") as f:
    story = f.read()

words = []
start_of_word = -1
target_start = "<"
target_end = ">"
for i , char in enumerate(story):   #enumerate gives us location of a char in the story
    if char == target_start:
        start_of_word = i
    if char == target_end and start_of_word != -1:
        word = story[start_of_word: i + 1]
        if word not in words:
            words.append(word)
        start_of_word = -1


answers = {}
for word in words:
    key = word.strip("<>")
    answer = input("Enter a word for "+ key + ": ")
    answers[word] = answer

for word in words:
    story = story.replace(word, answers[word])

print("\n *****Final Story***** \n ")
print(story)