import random

def twodice_roll():
    return random.randint(1,6), random.randint(1,6)

def get_player_count():
    while True:
        players = input("Enter the number of players (2-4 ):  ")
        if players.isdigit():
            players = int(players)
            if 2<= players <=4:
                return players
            print("Must be between 2-4 players. ")
        else:
            print("Invalid input. Try again. ")

def main():
    max_score = 100
    players = get_player_count()
    player_scores = [0 for _ in range(players)]

    while max(player_scores)<max_score:
        for i in range(players):
            print(f"\nPlayer {i+1}'s turn!")
            print(f"Current total score: {player_scores[i]}\n")

            current_turn = 0

            while True:
                roll_choice = input("Want to Roll(y/n): ").lower()
                if roll_choice !='y':
                    break
                
                d1,d2 = twodice_roll()
                print(f"You rolled: {d1} and {d2}")

                #snake eyes -> full score reset if 1 hits
                if d1==1 and d2 ==1:
                    print("Snake Eyes! Your entire score resets to 0!")
                    current_turn = 0
                    player_scores[i] = 0 #full reset
                    break

                #any single 1 -> turns ends, lose turn points
                if d1 ==1 or d2 == 1:
                    print("Rolled a 1! Turn over , no points added.")
                    current_turn = 0
                    break

                #normal scoring
                roll_sum = d1 + d2
                current_turn += roll_sum
                print(f"Turn Score:{current_turn}")

            player_scores[i] += current_turn
            print(f"Total Score now : {player_scores[i]}")

            if player_scores[i] >= max_score:
                break

    winner_score = max(player_scores)
    winner_idx = player_scores.index(winner_score)
    print(f"\n Congrat! Player {winner_idx+1} wins with {winner_score} points!")
if __name__ == "__main__":
    main()
