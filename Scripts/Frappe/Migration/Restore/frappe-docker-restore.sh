#!/bin/bash

# Frappe LMS Docker Restore Script

# Ask for inputs
read -p "Enter domain name (e.g., training.example.com): " DOMAIN
read -p "Enter backup folder path: " BACKUP_PATH

# Convert domain to underscore format for filenames
DOMAIN_UNDERSCORE=$(echo "$DOMAIN" | tr '.' '_')

# Set paths
DOCKER_DIR="/var/www/docker/frappe-lms/$DOMAIN"
CONTAINER="learning_prod_setup-backend-1"

# Show password file and ask for password
echo "=== Password file contents ==="
cat "$DOCKER_DIR/learning_prod_setup-passwords.txt"
echo ""
read -sp "Enter MySQL root password: " MYSQL_PWD
echo

echo "=== Step 1: Creating backup directory in container ==="
docker exec $CONTAINER mkdir -p /home/frappe/backups

echo "=== Step 2: Copying backup files to container ==="
docker cp "$BACKUP_PATH/." $CONTAINER:/home/frappe/backups/

echo "=== Step 3: Fixing permissions ==="
docker exec $CONTAINER chown -R frappe:frappe /home/frappe/backups/

echo "=== Step 4: Finding latest backup files ==="
DB_FILE=$(docker exec $CONTAINER bash -c "ls -t /home/frappe/backups/*${DOMAIN_UNDERSCORE}-database.sql.gz 2>/dev/null | head -1")
FILES_TAR=$(docker exec $CONTAINER bash -c "ls -t /home/frappe/backups/*${DOMAIN_UNDERSCORE}-files.tar 2>/dev/null | head -1")
PRIVATE_TAR=$(docker exec $CONTAINER bash -c "ls -t /home/frappe/backups/*${DOMAIN_UNDERSCORE}-private-files.tar 2>/dev/null | head -1")

echo "Database: $DB_FILE"
echo "Public files: $FILES_TAR"
echo "Private files: $PRIVATE_TAR"

if [ -z "$DB_FILE" ]; then
    echo "ERROR: No database backup found for $DOMAIN"
    exit 1
fi

echo "=== Step 5: Restoring backup ==="
docker exec $CONTAINER bench --site $DOMAIN restore \
    "$DB_FILE" \
    --with-public-files "$FILES_TAR" \
    --with-private-files "$PRIVATE_TAR" \
    --db-root-password "$MYSQL_PWD"

echo "=== Step 6: Running migrations ==="
docker exec $CONTAINER bench --site $DOMAIN migrate

echo "=== Step 7: Clearing caches ==="
docker exec $CONTAINER bench --site $DOMAIN clear-cache
docker exec $CONTAINER bench --site $DOMAIN clear-website-cache

echo "=== Step 8: Restarting containers ==="
cd "$DOCKER_DIR"
docker compose -f learning_prod_setup-compose.yml restart

echo "=== Restore complete! ==="
echo "Site: https://$DOMAIN"