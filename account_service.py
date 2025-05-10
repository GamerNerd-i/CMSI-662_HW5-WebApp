import sqlite3

"""
SQL INJECTION: Paramaterized values using (?), as shown below, are automatically protected
from SQL injection attacks.
"""


def get_balance(account_number, owner):
    try:
        con = sqlite3.connect("bank.db")
        cur = con.cursor()
        cur.execute(
            """
            SELECT balance FROM accounts where id=? and owner=?""",
            (account_number, owner),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return row[0]
    finally:
        con.close()


def do_transfer(source, target, amount):
    try:
        con = sqlite3.connect("bank.db")
        cur = con.cursor()
        cur.execute(
            """
            SELECT id FROM accounts where id=?""",
            (target,),
        )
        row = cur.fetchone()
        if row is None:
            return False
        cur.execute(
            """
            UPDATE accounts SET balance=balance-? where id=?""",
            (amount, source),
        )
        cur.execute(
            """
            UPDATE accounts SET balance=balance+? where id=?""",
            (amount, target),
        )
        con.commit()
        return True
    finally:
        con.close()


def get_user_accounts(owner):
    try:
        con = sqlite3.connect("bank.db")
        cur = con.cursor()
        cur.execute(
            """
            SELECT id, balance FROM accounts WHERE owner=? ORDER BY id""",
            (owner,),
        )
        rows = cur.fetchall()
        accounts = [{"id": row[0], "balance": row[1]} for row in rows]
        return accounts
    finally:
        con.close()
