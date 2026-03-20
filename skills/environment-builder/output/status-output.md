# Output Specification

After setup is complete, two things must be done: **terminal output summary** + **write file to project directory**.

**Writing the file is mandatory and cannot be skipped.** After the user closes the terminal, this file is the only reference.

---

## 1. Terminal Summary

Output the following in the terminal so the user can see results immediately:

```
Environment Status: READY / PARTIAL / FAILED

Running Services
- Web App: http://localhost:<port> (<framework>)
- Database: localhost:<port> (<db_type>)

Activate Command: conda activate <env_name> / source <path>/bin/activate
Start Command: <actual start command>
Stop Command: <actual stop command>

Detailed documentation saved to: ${PROJECT_DIR}/ENVIRONMENT_SETUP.md
```

---

## 2. Write ENVIRONMENT_SETUP.md (Mandatory)

**Must** use the Write tool to write the following content to `${PROJECT_DIR}/ENVIRONMENT_SETUP.md`.

This is the user's future operation manual; write it clearly and completely. Fill in based on the actual setup; skip sections that don't apply.

```markdown
# <Project Name> Environment Setup Documentation

> Setup Time: <date>
> Setup Method: env-setup agent

---

## Environment Information

| Item | Value |
|------|-----|
| Project Location | <absolute path of PROJECT_DIR> |
| Language | <language and version> |
| Framework | <framework and version> |
| Environment Type | conda / venv / Docker / system |
| Environment Name | <env_name> (if applicable) |
| Python Version | <version> (if applicable) |
| Node Version | <version> (if applicable) |
| GPU | <model and VRAM, or "none"> |

---

## Daily Usage

### Activate Environment

<Write based on actual setup, for example:>

```bash
conda activate setup_<project_name>
# Or
source <PROJECT_DIR>/venv/bin/activate
```

### Start Project

```bash
<actual start command, e.g. python manage.py runserver 0.0.0.0:8000>
```

### Stop Project

```bash
<actual stop command, e.g. Ctrl+C or docker compose down>
```

### Restart Project

```bash
<actual restart command>
```

### Access URLs

- Web: http://localhost:<port>
- API: http://localhost:<port>/api (if applicable)
- Database: localhost:<db_port> (if applicable)

---

## Database Information (If Applicable)

| Item | Value |
|------|-----|
| Type | PostgreSQL / MySQL / SQLite / MongoDB / Redis |
| Host | localhost |
| Port | <port> |
| Database Name | <db_name> |
| Username | <username> |
| Password | <password> |
| Connection Command | <e.g. psql -h localhost -p 5432 -U user -d dbname> |

---

## Environment Variables

Environment variable file used by the project: `<.env file path>`

Key variable descriptions:

| Variable | Value | Description |
|------|-----|------|
| DATABASE_URL | <value> | Database connection string |
| SECRET_KEY | <value> | Application secret key |
| ... | ... | ... |

---

## Setup Process Log

The following are key operations performed during setup, for reference when troubleshooting or re-setting up.

### Key Steps Executed

1. <Step 1: e.g. "Created conda environment setup_xxx, Python 3.10">
2. <Step 2: e.g. "uv pip install -r requirements.txt (inside Docker container)">
3. <Step 3: e.g. "Started PostgreSQL container, port 5432">
4. <Step 4: e.g. "Executed database migration python manage.py migrate">
5. ...

### Issues Encountered and Solutions

<If issues were encountered and resolved during setup, record them here. If no issues, write "Setup completed smoothly, no issues encountered.">

| Issue | Solution |
|------|---------|
| <issue description> | <how it was resolved> |

---

## Cleanup Method

To completely uninstall this environment:

```bash
<generate based on actual setup, for example:>

# Stop and remove containers
docker rm -f setup_<project_name>_postgres 2>/dev/null

# Remove Docker network
docker network rm setup_net_<project_name> 2>/dev/null

# Remove conda environment
conda env remove -n setup_<project_name> -y

# Remove workspace (not source code)
rm -rf <PROJECT_DIR>/.workspace
```
```

---

## Full Cleanup Commands (Cross-Project)

The following commands clean up all resources created by env-setup:

```bash
# Stop all setup containers
docker rm -f $(docker ps -a --filter "name=setup_" -q) 2>/dev/null

# Remove all setup networks
docker network ls --filter "name=setup_net_" -q | xargs -r docker network rm 2>/dev/null

# Remove conda environments (only those with setup_ prefix, does not touch user's existing environments)
conda env list 2>/dev/null | grep "^setup_" | awk '{print $1}' | xargs -I{} conda env remove -n {} -y 2>/dev/null

# Remove setup directories (in local project mode, do not delete source directory, only delete .workspace)
# Clone mode: rm -rf ${SETUP_ROOT}/
# Local mode:   rm -rf ${PROJECT_DIR}/.workspace

echo "All environments cleaned up"
```
