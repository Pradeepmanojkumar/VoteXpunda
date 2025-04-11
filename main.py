import tkinter as tk
from tkinter import ttk, messagebox, Frame, Label, Button, Listbox, Scrollbar, StringVar, Entry, END
import customtkinter as ctk
from datetime import datetime
import json
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

# Fix CustomTkinter version compatibility
ctk.deactivate_automatic_dpi_awareness()

# Constants and Configuration
APP_CONFIG = {
    'window_size': '1000x700',
    'title': 'VoteX - Voting System',
    'theme': 'dark',
    'color_theme': 'blue'
}

STYLES = {
    'header_font': ('Arial', 24, 'bold'),
    'normal_font': ('Arial', 12),
    'button_font': ('Arial', 14, 'bold'),
    'colors': {
        'primary': ['#3366ff', '#0044cc'],
        'success': ['#00cc44', '#009933'],
        'danger': ['#ff3333', '#cc0000'],
        'background': ['#1a1a1a', '#2d2d2d']
    }
}

# Add these constants at the top with other configs
FONT_CONFIG = {
    'title': ('Helvetica', 24, 'bold'),
    'subtitle': ('Helvetica', 20, 'bold'),
    'heading': ('Helvetica', 16, 'bold'),
    'normal': ('Helvetica', 12),
    'button': ('Helvetica', 14, 'bold')
}

# Helpers
class Utils:
    @staticmethod
    def validate_email(email):
        import re  # Move re import here
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return bool(re.match(pattern, email))
    
    @staticmethod
    def hash_password(password):
        import hashlib  # Move hashlib import here
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def create_gradient_frame(parent, colors):
        frame = ctk.CTkFrame(parent, fg_color=colors)
        return frame

def format_date(date):
    return date.strftime("%Y-%m-%d")

def generate_uuid():
    import uuid  # Move uuid import here
    return str(uuid.uuid4())

class DataManager:
    @staticmethod
    def save_to_json(data, filename):
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
    
    @staticmethod
    def load_from_json(filename):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    @classmethod
    def save_users(cls, users):
        user_data = {
            email: {
                'name': user.name,
                'email': user.email,
                'password': user.password,
                'role': user.role,
            } for email, user in users.items()
        }
        cls.save_to_json(user_data, 'users.json')
    
    @classmethod
    def load_users(cls):
        user_data = cls.load_from_json('users.json')
        users = {}
        for email, data in user_data.items():
            users[email] = User(
                name=data['name'],
                email=data['email'],
                password=data['password'],
                role=data.get('role', 'User')
            )
        return users
    
    @classmethod
    def save_elections(cls, elections):
        election_data = {}
        for idx, election in enumerate(elections):
            election_data[str(idx)] = {
                'title': election.title,
                'description': election.description,
                'start_date': election.start_date.strftime("%Y-%m-%d %H:%M:%S"),
                'end_date': election.end_date.strftime("%Y-%m-%d %H:%M:%S"),
                'candidates': election.candidates,
            }
        cls.save_to_json(election_data, 'elections.json')
    
    @classmethod
    def load_elections(cls):
        election_data = cls.load_from_json('elections.json')
        elections = []
        for _, data in election_data.items():
            elections.append(Election(
                title=data['title'],
                description=data['description'],
                start_date=datetime.strptime(data['start_date'], "%Y-%m-%d %H:%M:%S"),
                end_date=datetime.strptime(data['end_date'], "%Y-%m-%d %H:%M:%S"),
                candidates=data['candidates']
            ))
        return elections

users = {}  # Start with an empty dictionary

# Models
class User:
    def __init__(self, name, email, password, role='User'):
        self.name = name
        self.email = email
        self.password = password
        self.role = role
    
    def is_admin(self):
        return self.role == 'Admin'
        
    def to_dict(self):
        return {
            'name': self.name,
            'email': self.email,
            'password': self.password,
            'role': self.role,
        }

class Election:
    def __init__(self, title, description, start_date, end_date, candidates):
        self.title = title
        self.description = description
        self.start_date = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S") if isinstance(start_date, str) else start_date
        self.end_date = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S") if isinstance(end_date, str) else end_date
        self.candidates = candidates
        self.votes = {candidate: 0 for candidate in candidates}
    
    def is_active(self):
        now = datetime.now()
        return self.start_date <= now <= self.end_date
    
    def to_dict(self):
        return {
            'title': self.title,
            'description': self.description,
            'start_date': self.start_date.strftime("%Y-%m-%d %H:%M:%S"),
            'end_date': self.end_date.strftime("%Y-%m-%d %H:%M:%S"),
            'candidates': self.candidates,
            'votes': self.votes
        }

class Poll:
    def __init__(self, title, description, options, creator):
        self.title = title
        self.description = description
        self.options = options
        self.creator = creator
        self.votes = {option: 0 for option in options}
        self.voters = []

# Views
class AuthView(ctk.CTkFrame):
    def __init__(self, master, login_callback):
        super().__init__(master)
        self.login_callback = login_callback
        self.data_manager = DataManager()
        self.init_ui()
        
    def init_ui(self):
        self.container = ctk.CTkFrame(self)
        self.container.pack(pady=20, padx=20, fill="both", expand=True)
        self.current_frame = None
        self.create_login_form()
        self.create_registration_form()
        self.show_login()
        
    def create_login_form(self):
        self.login_frame = ctk.CTkFrame(self.container)
        ctk.CTkLabel(self.login_frame, text="Login to VoteX", font=("Arial", 24, "bold")).pack(pady=20)
        
        self.login_username = ctk.CTkEntry(self.login_frame, placeholder_text="Username", width=300)
        self.login_username.pack(pady=10)
        
        self.login_password = ctk.CTkEntry(self.login_frame, placeholder_text="Password", show="*", width=300)
        self.login_password.pack(pady=10)
        
        ctk.CTkButton(self.login_frame, text="Login", command=self.handle_login, width=200).pack(pady=20)
        ctk.CTkButton(self.login_frame, text="Don't have an account? Register", 
                     command=self.show_register, fg_color="transparent").pack()
        
    def create_registration_form(self):
        self.register_frame = ctk.CTkFrame(self.container)
        
        ctk.CTkLabel(self.register_frame, text="Create Account", font=("Arial", 24, "bold")).pack(pady=20)
        
        self.reg_username = ctk.CTkEntry(self.register_frame, placeholder_text="Username", width=300)
        self.reg_username.pack(pady=10)
        
        self.reg_email = ctk.CTkEntry(self.register_frame, placeholder_text="Email", width=300)
        self.reg_email.pack(pady=10)
        
        self.reg_password = ctk.CTkEntry(self.register_frame, placeholder_text="Password", show="*", width=300)
        self.reg_password.pack(pady=10)
        
        self.reg_confirm_password = ctk.CTkEntry(self.register_frame, placeholder_text="Confirm Password", 
                                               show="*", width=300)
        self.reg_confirm_password.pack(pady=10)
        
        ctk.CTkButton(self.register_frame, text="Register", command=self.handle_register, width=200).pack(pady=20)
        ctk.CTkButton(self.register_frame, text="Already have an account? Login", 
                     command=self.show_login, fg_color="transparent").pack()
        
    def show_login(self):
        if self.current_frame:
            self.current_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)
        self.current_frame = self.login_frame
        
    def show_register(self):
        if self.current_frame:
            self.current_frame.pack_forget()
        self.register_frame.pack(fill="both", expand=True)
        self.current_frame = self.register_frame
        
    def handle_login(self):
        username = self.login_username.get()
        password = self.login_password.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        hashed_password = Utils.hash_password(password)
        # Check if user exists and password matches
        logged_in_user = None
        for user in users.values():
            if user.name == username and user.password == hashed_password:
                logged_in_user = user
                messagebox.showinfo("Success", f"Welcome back, {username}!")
                self.login_callback(logged_in_user)  # We'll create this method
                return
        messagebox.showerror("Error", "Invalid username or password")
        
    def handle_register(self):
        username = self.reg_username.get()
        email = self.reg_email.get()
        password = self.reg_password.get()
        confirm_password = self.reg_confirm_password.get()
        
        # Validate input
        if not all([username, email, password, confirm_password]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        if not Utils.validate_email(email):
            messagebox.showerror("Error", "Invalid email format")
            return
        
        if email in users:
            messagebox.showerror("Error", "Email already registered")
            return
        
        # Create new user
        hashed_password = Utils.hash_password(password)
        new_user = User(username, email, hashed_password)
        users[email] = new_user
        
        # Save to JSON file
        DataManager.save_users(users)
        
        messagebox.showinfo("Success", "Registration successful! Please login.")
        self.show_login()
        
        # Clear registration form
        self.reg_username.delete(0, END)
        self.reg_email.delete(0, END)
        self.reg_password.delete(0, END)
        self.reg_confirm_password.delete(0, END)

class ElectionView(Frame):
    def __init__(self, master):
        super().__init__(master)
        self.init_ui()
        
    def init_ui(self):
        self.pack(fill="both", expand=True)
        Label(self, text="Available Elections", font=("Arial", 16)).pack(pady=10)
        
        self.election_listbox = Listbox(self, width=50, height=15)
        self.election_listbox.pack(pady=10)

        scrollbar = Scrollbar(self.election_listbox)
        scrollbar.pack(side="right", fill="y")
        self.election_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.election_listbox.yview)
        
        Button(self, text="View Election Details", command=self.view_election).pack(pady=5)
        
    def view_election(self):
        selected = self.election_listbox.curselection()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select an election to view.")
            return

class UserView(Frame):
    def __init__(self, master):
        super().__init__(master)
        self.init_ui()
        
    def init_ui(self):
        self.pack(fill="both", expand=True)

        self.user_listbox = Listbox(self)
        self.user_listbox.pack(side="left", fill="both", expand=True)

        scrollbar = Scrollbar(self)
        scrollbar.pack(side="right", fill="y")

        self.user_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.user_listbox.yview)

        Label(self, text="User Information").pack()

        self.user_name_var = StringVar()
        self.user_email_var = StringVar()

        Label(self, text="Name:").pack()
        Entry(self, textvariable=self.user_name_var).pack()

        Label(self, text="Email:").pack()
        Entry(self, textvariable=self.user_email_var).pack()

        Button(self, text="Update User", command=self.update_user).pack()
        Button(self, text="Delete User", command=self.delete_user).pack()

        self.user_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        
    def on_user_select(self, event):
        selected = self.user_listbox.curselection()
        if selected:
            # Handle user selection
            pass
        
    def update_user(self):
        selected = self.user_listbox.curselection()
        if selected:
            name = self.user_name_var.get()
            email = self.user_email_var.get()
            messagebox.showinfo("Success", "User updated successfully.")
        
    def delete_user(self):
        selected = self.user_listbox.curselection()
        if selected:
            messagebox.showinfo("Success", "User deleted successfully.")

class PollView(Frame):
    def __init__(self, master, current_user):
        super().__init__(master)
        self.current_user = current_user
        self.polls = []
        self.init_ui()
        
    def logout(self):
        """Handle logout functionality"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            # Clear current user data
            self.current_user = None
            # Destroy current view
            self.destroy()
            # Return to auth view (you might need to implement this callback through constructor)
            if hasattr(self.master, 'show_auth_view'):
                self.master.show_auth_view()
            else:
                messagebox.showinfo("Logout", "Please restart the application to login again.")
                self.master.quit()
                
    def init_ui(self):
        self.pack(fill="both", expand=True)
        
        # Top Frame with gradient effect
        top_frame = ctk.CTkFrame(self, fg_color=["#1a1a1a", "#2d2d2d"])
        top_frame.pack(side="top", fill="x", padx=0, pady=0)
        
        # User info with better styling
        user_info = f"Welcome, {self.current_user.name}"
        role_info = f"Role: {self.current_user.role}"
        ctk.CTkLabel(top_frame, text=user_info, font=("Arial", 16, "bold"), 
                     text_color=["#ffffff", "#e0e0e0"]).pack(side="left", padx=20, pady=10)
        ctk.CTkLabel(top_frame, text=role_info, font=("Arial", 12), 
                     text_color=["#cccccc", "#b0b0b0"]).pack(side="left", padx=5, pady=10)
        
        # Logout button with hover effect
        logout_btn = ctk.CTkButton(top_frame, text="Logout", width=100,
                                  fg_color=["#ff3333", "#cc0000"],
                                  hover_color=["#cc0000", "#990000"],
                                  command=self.logout)
        logout_btn.pack(side="right", padx=20, pady=10)
        
        # Main content area
        content_frame = ctk.CTkFrame(self)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Split into left and right panels
        left_panel = ctk.CTkFrame(content_frame)
        left_panel.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        right_panel = ctk.CTkFrame(content_frame)
        right_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # Create Poll Section
        poll_create_frame = ctk.CTkFrame(left_panel)
        poll_create_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(poll_create_frame, text="Create New Poll", 
                     font=("Arial", 20, "bold")).pack(pady=10)
        
        self.title_entry = ctk.CTkEntry(poll_create_frame, placeholder_text="Poll Title",
                                       height=40, font=("Arial", 14))
        self.title_entry.pack(fill="x", padx=20, pady=5)
        
        self.desc_entry = ctk.CTkEntry(poll_create_frame, placeholder_text="Poll Description",
                                      height=40, font=("Arial", 14))
        self.desc_entry.pack(fill="x", padx=20, pady=5)
        
        # Options Section with better styling
        options_frame = ctk.CTkFrame(poll_create_frame)
        options_frame.pack(fill="x", padx=20, pady=10)
        
        self.options_list = []
        
        def add_option():
            option_frame = ctk.CTkFrame(options_frame)
            option_frame.pack(fill="x", pady=2)
            
            option_entry = ctk.CTkEntry(option_frame, placeholder_text=f"Option {len(self.options_list) + 1}",
                                      height=35, font=("Arial", 12))
            option_entry.pack(side="left", padx=5, expand=True)
            
            def remove_option():
                self.options_list.remove(option_entry)
                option_frame.destroy()
                
            remove_btn = ctk.CTkButton(option_frame, text="×", width=35, height=35,
                                      fg_color=["#ff3333", "#cc0000"],
                                      hover_color=["#cc0000", "#990000"],
                                      command=remove_option)
            remove_btn.pack(side="right", padx=5)
            
            self.options_list.append(option_entry)
        
        # Add Option button with icon
        add_btn = ctk.CTkButton(options_frame, text="+ Add Option",
                               fg_color=["#00cc44", "#009933"],
                               hover_color=["#009933", "#006622"],
                               command=add_option)
        add_btn.pack(pady=10)
        
        # Initial options
        for _ in range(2):
            add_option()
        
        # Create Poll button
        create_btn = ctk.CTkButton(poll_create_frame, text="Create Poll",
                                  height=45, font=("Arial", 14, "bold"),
                                  fg_color=["#3366ff", "#0044cc"],
                                  hover_color=["#0044cc", "#003399"],
                                  command=self.create_poll)
        create_btn.pack(pady=20, padx=20)
        
        # Polls List Section
        polls_frame = ctk.CTkFrame(right_panel)
        polls_frame.pack(fill="both", expand=True)
        
        ctk.CTkLabel(polls_frame, text="Available Polls",
                     font=("Arial", 20, "bold")).pack(pady=10)
        
        # Custom listbox styling
        self.polls_listbox = Listbox(polls_frame, 
                                    bg="#2d2d2d",
                                    fg="#ffffff",
                                    selectbackground="#3366ff",
                                    selectforeground="#ffffff",
                                    font=("Arial", 12),
                                    borderwidth=0,
                                    highlightthickness=0)
        self.polls_listbox.pack(pady=5, padx=20, fill="both", expand=True)
        
        # Action buttons
        button_frame = ctk.CTkFrame(polls_frame)
        button_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkButton(button_frame, text="Vote",
                      fg_color=["#3366ff", "#0044cc"],
                      hover_color=["#0044cc", "#003399"],
                      command=self.vote_poll).pack(side="left", padx=5)
        
        ctk.CTkButton(button_frame, text="View Stats",
                      fg_color=["#00cc44", "#009933"],
                      hover_color=["#009933", "#006622"],
                      command=self.show_stats).pack(side="left", padx=5)
        
        if self.current_user.role == "Admin":
            ctk.CTkButton(button_frame, text="Delete Poll",
                         fg_color=["#ff3333", "#cc0000"],
                         hover_color=["#cc0000", "#990000"],
                         command=self.delete_poll).pack(side="left", padx=5)
        
        self.load_polls()
        
    def create_poll(self):
        title = self.title_entry.get()
        description = self.desc_entry.get()
        options = [opt.get() for opt in self.options_list if opt.get().strip()]
        
        if not all([title, description, options]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        poll = Poll(title, description, options, self.current_user.name)
        self.polls.append(poll)
        self.save_polls()
        self.load_polls()
        
        # Clear entries
        self.title_entry.delete(0, END)
        self.desc_entry.delete(0, END)
        for opt in self.options_list:
            opt.delete(0, END)
        
    def create_popup_window(self, title, size="400x500"):
        """Helper method to create consistent popup windows"""
        popup = ctk.CTkToplevel()
        popup.title(title)
        popup.geometry(size)
        
        # Make popup stay on top and grab focus
        popup.transient(self.winfo_toplevel())
        popup.grab_set()
        
        # Center the window on screen
        popup.update_idletasks()
        width = popup.winfo_width()
        height = popup.winfo_height()
        x = (popup.winfo_screenwidth() // 2) - (width // 2)
        y = (popup.winfo_screenheight() // 2) - (height // 2)
        popup.geometry(f'+{x}+{y}')
        
        return popup

    def vote_poll(self):
        selection = self.polls_listbox.curselection()
        if not selection:
            messagebox.showwarning("Error", "Please select a poll")
            return
        
        poll = self.polls[selection[0]]
        if self.current_user.name in poll.voters:
            messagebox.showwarning("Error", "You have already voted in this poll")
            return
        
        # Create voting dialog using the helper method
        vote_window = self.create_popup_window("Vote")
        
        # Header with better fonts
        ctk.CTkLabel(
            vote_window, 
            text=poll.title,
            font=FONT_CONFIG['title']
        ).pack(pady=20)
        
        ctk.CTkLabel(
            vote_window, 
            text=poll.description,
            font=FONT_CONFIG['normal']
        ).pack(pady=10)
        
        var = tk.StringVar()
        for option in poll.options:
            ctk.CTkRadioButton(
                vote_window, 
                text=option,
                variable=var, 
                value=option,
                font=FONT_CONFIG['normal']
            ).pack(pady=10)
        
        def submit_vote():
            choice = var.get()
            if choice:
                poll.votes[choice] += 1
                poll.voters.append(self.current_user.name)
                self.save_polls()
                messagebox.showinfo("Success", "Vote recorded!")
                vote_window.destroy()
        
        ctk.CTkButton(
            vote_window, 
            text="Submit Vote",
            width=200, 
            height=40,
            font=FONT_CONFIG['button'],
            command=submit_vote
        ).pack(pady=20)
        
    def delete_poll(self):
        if self.current_user.role != "Admin":
            messagebox.showerror("Error", "Only admins can delete polls")
            return
        
        selection = self.polls_listbox.curselection()
        if not selection:
            messagebox.showwarning("Error", "Please select a poll")
            return
        
        self.polls.pop(selection[0])
        self.save_polls()
        self.load_polls()
        
    def save_polls(self):
        with open('polls.json', 'w') as f:
            polls_data = []
            for poll in self.polls:
                polls_data.append({
                    'title': poll.title,
                    'description': poll.description,
                    'options': poll.options,
                    'creator': poll.creator,
                    'votes': poll.votes,
                    'voters': poll.voters
                })
            json.dump(polls_data, f, indent=4)
            
    def load_polls(self):
        try:
            with open('polls.json', 'r') as f:
                polls_data = json.load(f)
                self.polls = []
                for data in polls_data:
                    poll = Poll(data['title'], data['description'], data['options'], data['creator'])
                    poll.votes = data['votes']
                    poll.voters = data['voters']
                    self.polls.append(poll)
        except FileNotFoundError:
            self.polls = []
            
        self.polls_listbox.delete(0, END)
        for poll in self.polls:
            self.polls_listbox.insert(END, f"{poll.title} (Created by: {poll.creator})")
            
    def show_stats(self):
        selection = self.polls_listbox.curselection()
        if not selection:
            messagebox.showwarning("Error", "Please select a poll")
            return
        
        poll = self.polls[selection[0]]
        total_votes = sum(poll.votes.values())
        
        # Create stats window using the helper method
        stats_window = self.create_popup_window(
            f"Poll Statistics - {poll.title}", 
            "1000x800"  # Increased size to accommodate graphs
        )
        
        # Create main container
        main_frame = ctk.CTkFrame(stats_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        ctk.CTkLabel(
            main_frame, 
            text="Poll Statistics",
            font=FONT_CONFIG['title']
        ).pack(pady=10)
        
        # Poll info
        info_frame = ctk.CTkFrame(main_frame)
        info_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(
            info_frame, 
            text=f"Title: {poll.title}",
            font=FONT_CONFIG['heading']
        ).pack(pady=5)
        ctk.CTkLabel(
            info_frame, 
            text=f"Created by: {poll.creator}",
            font=FONT_CONFIG['normal']
        ).pack(pady=5)
        
        # Create visualization frame
        viz_frame = ctk.CTkFrame(main_frame)
        viz_frame.pack(fill="both", expand=True, pady=10)
        
        # Create matplotlib figure
        fig = plt.Figure(figsize=(12, 5))
        
        # Bar Chart
        ax1 = fig.add_subplot(121)
        options = list(poll.votes.keys())
        votes = list(poll.votes.values())
        
        bars = ax1.bar(options, votes, color=STYLES['colors']['primary'][0])
        ax1.set_title('Vote Distribution', color='white')
        ax1.set_xlabel('Options', color='white')
        ax1.set_ylabel('Number of Votes', color='white')
        ax1.set_facecolor(STYLES['colors']['background'][0])
        
        # Style the bar chart
        ax1.spines['bottom'].set_color('white')
        ax1.spines['top'].set_color('white')
        ax1.spines['left'].set_color('white')
        ax1.spines['right'].set_color('white')
        ax1.tick_params(colors='white')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}',
                    ha='center', va='bottom', color='white')
        
        # Rotate x-axis labels if needed
        plt.setp(ax1.get_xticklabels(), rotation=45, ha='right')
        
        # Pie Chart
        ax2 = fig.add_subplot(122)
        if total_votes > 0:
            wedges, texts, autotexts = ax2.pie(votes, 
                                              labels=options,
                                              autopct='%1.1f%%',
                                              colors=plt.cm.Pastel1(np.linspace(0, 1, len(options))))
            plt.setp(autotexts, color='black', weight='bold')
            plt.setp(texts, color='white')
        else:
            ax2.pie([1], labels=['No votes'], colors=['gray'])
        
        ax2.set_title('Vote Percentage Distribution', color='white')
        
        # Style the figure
        fig.patch.set_facecolor(STYLES['colors']['background'][0])
        
        # Create canvas
        canvas = FigureCanvasTkAgg(fig, master=viz_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Stats details with better fonts
        stats_frame = ctk.CTkFrame(main_frame)
        stats_frame.pack(fill="x", pady=10)
        
        for option, votes in poll.votes.items():
            percentage = (votes / total_votes * 100) if total_votes > 0 else 0
            ctk.CTkLabel(
                stats_frame,
                text=f"{option}: {votes} votes ({percentage:.1f}%)",
                font=FONT_CONFIG['normal']
            ).pack(pady=2)
        
        ctk.CTkLabel(
            main_frame,
            text=f"Total Votes: {total_votes}",
            font=FONT_CONFIG['heading']
        ).pack(pady=10)
        
        # Close button
        ctk.CTkButton(
            main_frame, 
            text="Close",
            command=stats_window.destroy,
            width=100,
            font=FONT_CONFIG['button']
        ).pack(pady=10)

class MainView:
    def __init__(self, root):
        self.root = root
        self.root.title("VoteX - Voting System")
        self.root.geometry("1000x700")
        
        # Set theme and color scheme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Configure grid
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Initialize user data
        self.current_user = None
        users.update(DataManager.load_users())
        
        self.create_widgets()
        
        # Handle high DPI displays
        self.root.update_idletasks()
        
    def show_auth_view(self):
        """Show authentication view after logout"""
        # Remove all tabs
        for tab in self.tab_control.tabs():
            self.tab_control.forget(tab)
        # Re-create auth view
        self.auth_view = AuthView(self.tab_control, self.switch_to_main_view)
        self.tab_control.add(self.auth_view, text='Authentication')
        self.current_user = None
        
    def create_widgets(self):
        self.tab_control = ttk.Notebook(self.root)
        
        self.auth_view = AuthView(self.tab_control, self.switch_to_main_view)
        self.poll_view = None  # Will be created after login
        self.user_view = None  # Will be created after login
        
        self.tab_control.add(self.auth_view, text='Authentication')
        self.tab_control.pack(expand=1, fill='both')

    def switch_to_main_view(self, user):
        self.current_user = user
        self.tab_control.forget(self.auth_view)
        
        self.poll_view = PollView(self.tab_control, self.current_user)
        self.tab_control.add(self.poll_view, text='Polls')
        
        if self.current_user.role == "Admin":
            self.user_view = UserView(self.tab_control)
            self.tab_control.add(self.user_view, text='Users')
        
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = MainView(root)
    app.run()