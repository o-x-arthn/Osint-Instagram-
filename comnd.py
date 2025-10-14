import cmd
import os
import sqlite3
import json
from datetime import datetime
import asyncio
from pathlib import Path
from typing import Dict, List, Any
from osint import Arthn_get_full_user_info, Arthn_logout, Arthn_store_session, Arthn_store_sensitive_data, Arthn_store_target
from info import format_output

global current_session_id, current_target, command_history
current_session_id = None
current_target = None
command_history = []

class ArthnOSINTShell(cmd.Cmd):
    def __init__(self):
        super().__init__()
        self.update_prompt()

    def update_prompt(self):
        self.prompt = f"\033[1;92m┌──(\033[1;94mosint㉿osint\033[1;92m)-[\033[1;93mosint_arthn\033[1;92m]\n└─#\033[0m "

    def preloop(self):
        print("\033[1;92m" + "="*60 + "\nArthn’s OSINT BEAST\n" + "="*60 + "\033[0m")
        print("\033[1;91mWARNING: Use responsibly and comply with Instagram’s terms and laws.\033[0m")
        self.update_prompt()

    def do_set_session(self, arg):
        global current_session_id
        if not arg:
            print("\033[1;91m[-] Usage: set_session <sessionid>\033[0m")
            return
        current_session_id = arg
        print(f"\033[1;92m[+] Session set with sessionid: {arg}\033[0m")
        asyncio.run(Arthn_store_session("unknown", current_session_id, {}))
        self.update_prompt()
        command_history.append(f"set_session {arg}")

    def do_set_target(self, arg):
        global current_target
        args = arg.split()
        if len(args) != 2:
            print("\033[1;91m[-] Usage: set_target <username> <followers>\033[0m")
            return
        username, followers = args
        try:
            followers = int(followers)
            current_target = {"username": username, "followers": followers}
            asyncio.run(Arthn_store_target(username, followers))
            print(f"\033[1;92m[+] Target set: @{username} with {followers} followers\033[0m")
            command_history.append(f"set_target {username} {followers}")
        except ValueError:
            print("\033[1;91m[-] Followers must be a number\033[0m")

    def do_set_scan_target(self, arg):
        args = arg.split()
        if len(args) != 2:
            print("\033[1;91m[-] Usage: set_scan_target <username> <followers>\033[0m")
            return
        self.do_set_target(arg)
        if current_target:
            self.do_scan_target("")
        command_history.append(f"set_scan_target {arg}")

    def do_scan_target(self, arg):
        if not current_session_id or not current_target:
            print("\033[1;91m[-] Set session and target first\033[0m")
            return
        try:
            data, follower_relationships = asyncio.run(
                Arthn_get_full_user_info(current_target["username"], current_session_id, current_target["followers"])
            )
            if "error" in data:
                print(f"\033[1;91m[-] Error: {data['error']}\033[0m")
            else:
                # Use format_output from info.py
                print(format_output(data, current_target["followers"], follower_relationships))
                # Store sensitive data if found
                sensitive = data.get('additional_sensitive_data', {})
                for key, value in sensitive.items():
                    if value and key != 'cookies':
                        asyncio.run(Arthn_store_sensitive_data(current_target["username"], key, str(value)))
            command_history.append("scan_target")
        except Exception as e:
            print(f"\033[1;91m[-] Error during scan: {str(e)}\033[0m")

    def do_logout(self, arg):
        global current_session_id
        if not current_session_id:
            print("\033[1;91m[-] No active session\033[0m")
            return
        success = asyncio.run(Arthn_logout(current_session_id))
        if success:
            current_session_id = None
            self.update_prompt()
            print("\033[1;92m[+] Logged out successfully\033[0m")
        else:
            print("\033[1;91m[-] Logout failed\033[0m")
        command_history.append("logout")

    def do_whoami(self, arg):
        if current_session_id:
            print(f"\033[1;94mCurrent Session ID:\033[0m \033[1;93m{current_session_id}\033[0m")
        else:
            print("\033[1;91m[-] No active session\033[0m")
        command_history.append("whoami")

    def do_ls(self, arg):
        conn = sqlite3.connect('darkstorm_data.db')
        c = conn.cursor()
        c.execute("SELECT username, timestamp FROM sessions")
        sessions = c.fetchall()
        c.execute("SELECT username, followers, timestamp FROM targets")
        targets = c.fetchall()
        print("\033[1;94mSessions:\033[0m")
        for session in sessions:
            print(f"\033[1;93m  {session[0]} - {session[1]}\033[0m")
        print("\033[1;94mTargets:\033[0m")
        for target in targets:
            print(f"\033[1;93m  {target[0]} - {target[1]} followers - {target[2]}\033[0m")
        conn.close()
        command_history.append("ls")

    def do_dir(self, arg):
        self.do_ls(arg)
        command_history.append("dir")

    def do_clear(self, arg):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\033[1;92m" + "="*60 + "\nArthn’s OSINT BEAST\n" + "="*60 + "\033[0m")
        command_history.append("clear")

    def do_cls(self, arg):
        self.do_clear(arg)
        command_history.append("cls")

    def do_pwd(self, arg):
        print(f"\033[1;94mWorking Directory:\033[0m \033[1;93m{os.getcwd()}\033[0m")
        command_history.append("pwd")

    def do_cat(self, arg):
        if not arg:
            print("\033[1;91m[-] Usage: cat <username>\033[0m")
            return
        conn = sqlite3.connect('darkstorm_data.db')
        c = conn.cursor()
        c.execute("SELECT * FROM sensitive_data WHERE username = ?", (arg,))
        data = c.fetchall()
        if data:
            print("\033[1;94mSensitive Data for {}:\033[0m".format(arg))
            for row in data:
                print(f"\033[1;93m  {row[1]}: {row[2]} - {row[3]}\033[0m")
        else:
            print(f"\033[1;91m[-] No data found for {arg}\033[0m")
        conn.close()
        command_history.append(f"cat {arg}")

    def do_rm(self, arg):
        if not arg:
            print("\033[1;91m[-] Usage: rm <username>\033[0m")
            return
        conn = sqlite3.connect('darkstorm_data.db')
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE username = ?", (arg,))
        c.execute("DELETE FROM sensitive_data WHERE username = ?", (arg,))
        c.execute("DELETE FROM targets WHERE username = ?", (arg,))
        conn.commit()
        if c.rowcount > 0:
            print(f"\033[1;92m[+] Removed data for {arg}\033[0m")
        else:
            print(f"\033[1;91m[-] No data found for {arg}\033[0m")
        conn.close()
        command_history.append(f"rm {arg}")

    def do_history(self, arg):
        print("\033[1;94mCommand History:\033[0m")
        for i, cmd in enumerate(command_history, 1):
            print(f"\033[1;93m  {i}. {cmd}\033[0m")
        command_history.append("history")

    def do_find(self, arg):
        if not arg:
            print("\033[1;91m[-] Usage: find <username>\033[0m")
            return
        conn = sqlite3.connect('darkstorm_data.db')
        c = conn.cursor()
        c.execute("SELECT username, timestamp FROM sessions WHERE username LIKE ?", (f"%{arg}%",))
        sessions = c.fetchall()
        c.execute("SELECT username, followers, timestamp FROM targets WHERE username LIKE ?", (f"%{arg}%",))
        targets = c.fetchall()
        if sessions or targets:
            print("\033[1;94mFound Sessions:\033[0m")
            for session in sessions:
                print(f"\033[1;93m  {session[0]} - {session[1]}\033[0m")
            print("\033[1;94mFound Targets:\033[0m")
            for target in targets:
                print(f"\033[1;93m  {target[0]} - {target[1]} followers - {target[2]}\033[0m")
        else:
            print(f"\033[1;91m[-] No results found for {arg}\033[0m")
        conn.close()
        command_history.append(f"find {arg}")

    def do_grep(self, arg):
        if not arg:
            print("\033[1;91m[-] Usage: grep <keyword>\033[0m")
            return
        conn = sqlite3.connect('darkstorm_data.db')
        c = conn.cursor()
        c.execute("SELECT username, data_type, data_value, timestamp FROM sensitive_data WHERE data_value LIKE ?", (f"%{arg}%",))
        results = c.fetchall()
        if results:
            print("\033[1;94mMatching Data:\033[0m")
            for row in results:
                print(f"\033[1;93m  {row[0]} - {row[1]}: {row[2]} - {row[3]}\033[0m")
        else:
            print(f"\033[1;91m[-] No matches found for {arg}\033[0m")
        conn.close()
        command_history.append(f"grep {arg}")

    def do_touch(self, arg):
        if not arg:
            print("\033[1;91m[-] Usage: touch <filename>\033[0m")
            return
        try:
            with open(arg, 'a'):
                os.utime(arg, None)
            print(f"\033[1;92m[+] Created/Updated {arg}\033[0m")
        except Exception as e:
            print(f"\033[1;91m[-] Error: {str(e)}\033[0m")
        command_history.append(f"touch {arg}")

    def do_cd(self, arg):
        global current_target
        if not arg:
            current_target = None
            print("\033[1;92m[+] Changed to root context\033[0m")
        else:
            conn = sqlite3.connect('darkstorm_data.db')
            c = conn.cursor()
            c.execute("SELECT username, followers FROM targets WHERE username = ?", (arg,))
            target = c.fetchone()
            if target:
                current_target = {"username": target[0], "followers": target[1]}
                print(f"\033[1;92m[+] Changed to target: @{arg}\033[0m")
            else:
                print(f"\033[1;91m[-] Target {arg} not found\033[0m")
            conn.close()
        command_history.append(f"cd {arg}")

    def do_who(self, arg):
        conn = sqlite3.connect('darkstorm_data.db')
        c = conn.cursor()
        c.execute("SELECT username, timestamp FROM sessions")
        sessions = c.fetchall()
        print("\033[1;94mActive Sessions:\033[0m")
        for session in sessions:
            print(f"\033[1;93m  {session[0]} - {session[1]}\033[0m")
        conn.close()
        command_history.append("who")

    def do_ps(self, arg):
        print("\033[1;94mRunning Processes:\033[0m")
        print("\033[1;93m  [No async processes tracked in this version]\033[0m")
        command_history.append("ps")

    def do_kill(self, arg):
        print("\033[1;91m[-] No processes to kill in this version\033[0m")
        command_history.append(f"kill {arg}")

    def do_export(self, arg):
        if not arg:
            print("\033[1;91m[-] Usage: export <filename>\033[0m")
            return
        conn = sqlite3.connect('darkstorm_data.db')
        c = conn.cursor()
        c.execute("SELECT * FROM sensitive_data")
        data = c.fetchall()
        with open(arg, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\033[1;92m[+] Exported data to {arg}\033[0m")
        conn.close()
        command_history.append(f"export {arg}")

    def do_import(self, arg):
        if not arg:
            print("\033[1;91m[-] Usage: import <filename>\033[0m")
            return
        try:
            with open(arg, 'r') as f:
                data = json.load(f)
            conn = sqlite3.connect('darkstorm_data.db')
            c = conn.cursor()
            for row in data:
                c.execute("INSERT INTO sensitive_data VALUES (?, ?, ?, ?)", row)
            conn.commit()
            print(f"\033[1;92m[+] Imported data from {arg}\033[0m")
            conn.close()
        except Exception as e:
            print(f"\033[1;91m[-] Error: {str(e)}\033[0m")
        command_history.append(f"import {arg}")

    def do_stats(self, arg):
        conn = sqlite3.connect('darkstorm_data.db')
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM sessions")
        session_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM targets")
        target_count = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM sensitive_data")
        data_count = c.fetchone()[0]
        print("\033[1;94mTool Statistics:\033[0m")
        print(f"\033[1;93m  Sessions: {session_count}\033[0m")
        print(f"\033[1;93m  Targets: {target_count}\033[0m")
        print(f"\033[1;93m  Sensitive Data Entries: {data_count}\033[0m")
        print(f"\033[1;93m  Commands Executed: {len(command_history)}\033[0m")
        conn.close()
        command_history.append("stats")

    def do_update(self, arg):
        print("\033[1;92m[+] Checking for updates...\033[0m")
        print("\033[1;93m  [Simulated] Tool is up to date\033[0m")
        command_history.append("update")

    def do_exit(self, arg):
        print("\033[1;92m[+] Exiting Arthn’s OSINT BEAST\033[0m")
        return True

    def do_quit(self, arg):
        self.do_exit(arg)
        command_history.append("quit")

    def do_help(self, arg):
        if arg:
            super().do_help(arg)
        else:
            print("\033[1;94mAvailable Commands:\033[0m")
            commands = [
                ("cat <username>", "Display sensitive data for a specified username from the database"),
                ("cd <username>", "Change context to a specific target username or to root if no argument"),
                ("clear", "Clear the terminal screen (alias for cls)"),
                ("cls", "Clear the terminal screen (alias for clear)"),
                ("dir", "List all sessions and targets (alias for ls)"),
                ("exit", "Exit the Arthn’s OSINT BEAST shell"),
                ("export <filename>", "Export sensitive data to a JSON file"),
                ("find <username>", "Search for sessions and targets matching a username pattern"),
                ("grep <keyword>", "Search for sensitive data containing a specific keyword"),
                ("history", "Show the command history"),
                ("import <filename>", "Import sensitive data from a JSON file into the database"),
                ("kill", "Placeholder to terminate processes (not implemented in this version)"),
                ("ls", "List all sessions and targets (alias for dir)"),
                ("logout", "Log out of the current session"),
                ("ps", "Display running processes (not implemented in this version)"),
                ("pwd", "Print the current working directory"),
                ("quit", "Exit the Arthn’s OSINT BEAST shell (alias for exit)"),
                ("rm <username>", "Remove session, target, and sensitive data for a specified username"),
                ("scan_target", "Scan the current target for Instagram data using the set session"),
                ("set_scan_target <username> <followers>", "Set and immediately scan a target Instagram username with estimated followers"),
                ("set_session <sessionid>", "Set the Instagram session ID for API requests"),
                ("set_target <username> <followers>", "Set a target Instagram username with estimated followers"),
                ("stats", "Display statistics about sessions, targets, and commands"),
                ("touch <filename>", "Create or update the timestamp of a file"),
                ("update", "Check for tool updates (simulated)"),
                ("who", "List all active sessions"),
                ("whoami", "Display the current session ID")
            ]
            for cmd, desc in sorted(commands, key=lambda x: x[0]):
                print(f"\033[1;93m  {cmd}\033[0m: {desc}")
            print("\033[1;94mType 'help <command>' for more details on a specific command.\033[0m")

    def default(self, line):
        print(f"\033[1;91m[-] Unknown command: {line}\033[0m")
        command_history.append(line)

if __name__ == '__main__':
    ArthnOSINTShell().cmdloop()
