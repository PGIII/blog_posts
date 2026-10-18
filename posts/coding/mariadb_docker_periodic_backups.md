+++
summary = "Setting up periodic backups of a MariaDB Database in a Docker container"
cover_image_url = "/post_assets/MariaDB_Docker_Periodic_Backups/https___mariadb.com_wp-content_uploads_2019_11_mariadb-logo_blue-transparent.png"
creation_date = 2023-07-12T20:15:02Z
modified_date = 2023-07-15T01:08:03Z
+++
## MariaDB Docker Periodic Backups

### Docker Compose Setup

***

In this example the Database container is configured through Docker compose

Make sure to mount a directory that will contain the backups, in this case we mount ./db_backup to
/var/mariadb/backup in the container

```yaml
db:
image: mariadb:10
restart: always
volumes:
    - ./data:/var/lib/mysql
    - ./db_backup:/var/mariadb/backup
    - ./config/db:/etc/mysql/conf.d
environment:
    MARIADB_ROOT_PASSWORD: password
    MARIADB_DATABASE: my_db
```

*This is a part of a larger docker-compose.yml*

### Backup Script

***

Next Lets create a backup script. This script will be somewhat generic and should work on both docker and
native
running instances of MySQL or MariaDB

The Script assumes the password is stored in MARIADB_ROOT_PASSWORD environment variable, which is common for
docker
setups

```bash
#!/bin/bash
sql_pw=$(printenv MARIADB_ROOT_PASSWORD)
backup_dir=/var/mariadb/backup

# How many days to keep backup for
keep_for_days=5

logfile=$backup_dir/backup.log
backup_file=$backup_dir/full-db-dump-$(date +%Y-%m-%d_%H-%M-%S).sql.gz

echo "$(date +%Y-%m-%d_%H-%M-%S) Backup Start" >> $logfile
#dump DB and compress with gzip
mysqldump --all-databases -uroot -p$sql_pw | gzip >> $backup_file
if [ $? == 0 ]; then
    echo "$(date +%Y-%m-%d_%H-%M-%S) sql backup done" >> $logfile
else
    echo [error] mysqldump returned error code $? >> $logfile
fi
# Delete old backups
find $backup_dir -mtime +$keep_for_days -delete
```

*run_backup.sh*

Now we need a script that will copy and execute the backup script in the DB docker container

seperating the two scripts makes the first more generic and easier to write

```bash
#!/bin/bash
docker cp /full_path_to_script/run_backup.sh db-container-name:/tmp/run_backup.sh
docker exec db-container-name ./tmp/run_backup.sh
```

*docker_run_backup.sh*

### Add Script To Crontab

***

Lastly we just need to add docker_run_backup.sh to roots crontab so that we have a periodic backup
run

```bash
sudo crontab -e
```

And then add the following line to your crontab file, this will run our script every day at midnight

```bash
0 0 * * * /path_to_script/docker_run_backup.sh
```

You now have your Docker MariaDB Container backing up every night
