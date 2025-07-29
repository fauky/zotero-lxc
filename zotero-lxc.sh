#!/bin/bash
#
# This script installs zotero backend services on a Ubuntu 24.04 OS
#
### Configuration Parameters
# These parameters are hardcoded in zotero sources,
# therefore, it is important to set them properly before building the source code.
#
# protocol: Possible values: http, https
# http:  Select this option if accessing locally wihtout the need for SSL encryption;
#        zotero will be accessible via http://domain, or http://192.168.x.x
#
# https: Select this option will generate self-signed certificate.
#        This will make zotero accessible via https://domain, or https://192.168.x.x
#
#        Web browsers will raise a warning for self-signed certificate,
#        but will ask for exception to be added.
#
#        Zotero Desktop client does not have an option to accept self-signed certificates.
#        This script creates patching scripts in /opt/zotero/scripts/directory. Running
#        those scripts on desktop computers should create appropriate 'cert_override.txt'
#        in Zotero Desktop client's profile directory which will allow it to connect via SSL.
#
# https: Also select https, if you are using a reverse proxy that handles SSL termination;
#        Point reverse proxy to port 80 on IP address of zotero's host, e.g. http://192.168.x.x:80
#        In this case, no exceptions are needed to be added for self-signed certificate
#
# domain: Possile values: xyz.com, zotero.xyz.com, zotero.local, zotero.lan, etc.
#         IP address can also be used as domain; zotero will be accessible via http(s)://192.168.x.x

# PHP version
php_version=8.3

## Elasticsearch configuration
es_version=9.x
es_Xms="256m"  # initial jvm heap size
es_Xmx="512m"  # max jvm heap size

# Zotero Installation Directory
install_dir=/var/www/zotero
scripts_dir=/opt/zotero/scripts

# Zotero services to install
services=(
  "dataserver"
  "stream-server"
  "translation-server"
  "attachment-proxy"
  "tinymce-clean-server"
  "full-text-indexer"
  "web-library"
)

# Zotero configuration
api_super_user=zotero
zotero_mysql_user=zotero

# Zotero internal ports
api_port=8080
stream_server_port=8081
web_library_port=8001
fulltext_indexer_port=9500
attachment_proxy_port=3000
htmlclean_server_port=16342

## MinIO configuration
aws_s3_region=us-east-1
minio_s3_port=9000
minio_ui_port=9001
minio_root_user="zotero"

# Generate random passwords
pass_length=16
zotero_mysql_password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c ${pass_length})
zotero_auth_salt=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c ${pass_length})
zotero_api_super_password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c ${pass_length})
minio_root_password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c ${pass_length})
mysql_root_password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c ${pass_length})

# This information is collected from user at runtime
domain=""
protocol=""
user_name=""
user_password=""

# These URLs are generated at runtime based after collecting user input
base_uri=""
api_url=""
api_authority=""
attachment_proxy_uri=""
stream_url=""
minio_ui_url=""

# cert_override.txt is generated at runtime based on protocol selection
cert_override=""

# Collect user input: domain, protocol, user name, password
collect_user_input() {
  # Show domain selection menu
  choice=$(whiptail --title "Select Domain Name" --menu "How would you like to access Zotero?" 15 60 3 \
    "1" "Use current hostname ($(hostname -f))" \
    "2" "Use current IP address ($(hostname -I | awk '{print $1}'))" \
    "3" "Enter domain name manually" 3>&1 1>&2 2>&3)

  [ $? -ne 0 ] && { echo "Installation cancelled. Exiting."; exit 1; }

  # Set domain name
  case "$choice" in
      1)  domain=$(hostname -f) ;;
      2)  domain=$(hostname -I | awk '{print $1}') ;;
      3)  while true; do
              domain=$(whiptail --inputbox "Enter domain name:" 10 60 3>&1 1>&2 2>&3)
              [ $? -ne 0 ] && { echo "Installation cancelled. Exiting."; exit 1; }
              if [[ -n "$domain" ]]; then
                  break
              else
                  whiptail --title "Input Error" --msgbox "Domain name cannot be empty. Please try again." 8 60
              fi
          done ;;
      *)  echo "How did it get here?" && exit 1;;
  esac

  # Show protocol information screen
  whiptail --title "Press OK to select protocol on next screen" --msgbox \
    "HTTP: Select this if you want to access zotero in a local environment and don't need SSL encryption.

HTTPS: Select this if you want to place zotero behind a reverse proxy or enable SSL encryption locally.

A self-signed certificate will also be genrated to access zotero at:  https://${domain}" 15 60

  # Select protocol
  protocol_choice=$(whiptail --title "Select Protocol" --menu "Select protocol for accessing zotero:" 12 40 2 \
    "1" "HTTP" \
    "2" "HTTPS" 3>&1 1>&2 2>&3)

  [ $? -ne 0 ] && { echo "Installation cancelled. Exiting."; exit 1; }

  # Assign protocol based on selection
  case "$protocol_choice" in
    1)  protocol="http" ;;
    2)  protocol="https" ;;
    *)  echo "How did it get here?" && exit 1;;
  esac

  # Prompt for user name
  while true; do
    user_name=$(whiptail --title "New Zotero Account Details: Username" --inputbox "Please enter user name to create your first zotero account:" 10 60 3>&1 1>&2 2>&3)
    [ $? -ne 0 ] && { echo "Installation cancelled. Exiting."; exit 1; }
    if [[ -n "$user_name" ]]; then
        break
    else
        whiptail --title "Input Error" --msgbox "Username cannot be empty. Please try again." 8 60
    fi
  done

  # Prompt for user password
  while true; do
    user_password=$(whiptail --title "New Zotero Account Details: Password" --passwordbox "Enter password for this zotero account:" 10 60 3>&1 1>&2 2>&3)
    [ $? -ne 0 ] && { echo "Installation cancelled. Exiting."; exit 1; }

    password_confirm=$(whiptail --title "New Zotero Account Details: Confirm Password" --passwordbox "Re-enter password for this zotero account:" 10 60 3>&1 1>&2 2>&3)
    [ $? -ne 0 ] && { echo "Installation cancelled. Exiting."; exit 1; }

    # Validation checks
    if [[ -z "$user_password" || -z "$password_confirm" ]]; then
        whiptail --title "Input Error" --msgbox "Password cannot be empty. Please try again." 8 60
        continue
    fi

    if [[ "$user_password" != "$password_confirm" ]]; then
        whiptail --title "Passwords Mismatch" --msgbox "Passwords do not match. Please try again." 8 60
        continue
    fi
    break
  done

  # generate urls based on selected protocol and domain name
  generate_urls
}

# Generate URLs based on collected user input
generate_urls() {
  base_uri="${protocol}://${domain}/"
  api_url="${protocol}://${domain}/api/"
  api_authority="${domain}/api/"
  attachment_proxy_uri="${protocol}://${domain}/fs/"
  stream_url="${protocol/http/ws}://${domain}/"
  minio_ui_url="${protocol}://${domain}/minio"
}

# Install Node.js
install_node_js() {
  # Configure Node.js repository
  curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
  apt update && apt install -y nodejs
}

# Install Elasticsearch
install_elasticsearch() {
  # Configure elasticsearch repository
  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/${es_version}/apt stable main" | sudo tee /etc/apt/sources.list.d/elasticsearch.list

  apt update && apt install -y elasticsearch
}

# Install MinIO
install_minio() {
  # Install MinIO Server
  wget https://dl.min.io/server/minio/release/linux-amd64/minio -O /usr/bin/minio
  chmod +x /usr/bin/minio

  # Install MinIO CLI
  wget -O /usr/bin/mc https://dl.min.io/client/mc/release/linux-amd64/mc
  chmod +x /usr/bin/mc
}

# Install all dependencies
install_os_packages() {
  apt update && apt -y upgrade
  apt install -y curl software-properties-common file \
    net-tools git git-lfs p7zip-full zip xz-utils zlib1g-dev binutils ncurses-bin xxd \
    php${php_version}-dev php${php_version}-xml php${php_version}-mbstring php${php_version}-mysql php${php_version}-memcached php${php_version}-curl php${php_version}-redis php${php_version}-igbinary php${php_version}-memcached \
    composer apache2 libapache2-mod-php${php_version} \
    mysql-server mysql-client redis-server memcached \
    libmemcached11 libmemcachedutil2 libmemcached-dev
}

# Configure Git
configure_git() {
  # Get rid of git error:  fatal: detected dubious ownership in repository at '...'
  git config --global safe.directory '*'
}

# Configure PHP
configure_php() {
  sed -i 's/memory_limit = 128M/memory_limit = 1G/g' /etc/php/${php_version}/apache2/php.ini
  sed -i 's/max_execution_time = 30/max_execution_time = 300/g' /etc/php/${php_version}/apache2/php.ini
  sed -i 's/short_open_tag = Off/short_open_tag = On/g' /etc/php/${php_version}/apache2/php.ini
  sed -i 's/short_open_tag = Off/short_open_tag = On/g' /etc/php/${php_version}/cli/php.ini
  sed -i 's/display_errors = On/display_errors = Off/g' /etc/php/${php_version}/apache2/php.ini
  sed -i 's/error_reporting = E_ALL \& ~E_DEPRECATED \& ~E_STRICT/error_reporting = E_ALL \& ~E_NOTICE \& ~E_STRICT \& ~E_DEPRECATED/g' /etc/php/${php_version}/apache2/php.ini
}

# Configure MySQL Server
configure_mysql() {
  mkdir -p /etc/mysql/mysql.conf.d
  cat <<'EOF' > /etc/mysql/mysql.conf.d/my.cnf
[mysqld]
sql_mode="STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"
EOF

  systemctl restart mysql.service
}

# Configure elasticsearch
configure_elasticsearch() {
  sed -i "s|^#\s*cluster\.name:.*|cluster.name: zotero|" /etc/elasticsearch/elasticsearch.yml
  sed -i "s|^#\s*node\.name:.*|node.name: zotero|" /etc/elasticsearch/elasticsearch.yml
  sed -i "s|^#\s*bootstrap\.memory_lock:.*|bootstrap.memory_lock: true|" /etc/elasticsearch/elasticsearch.yml
  sed -i "s|^xpack\.security\.enabled:.*|xpack.security.enabled: false|" /etc/elasticsearch/elasticsearch.yml
  sed -i "s|^cluster\.initial_master_nodes:.*|cluster.initial_master_nodes: \[\"zotero\"\]|" /etc/elasticsearch/elasticsearch.yml

  # Set JVM Heap size to 1GB
  sed -i "/JVM heap size/ {
  :a
  n
  /^$/!ba
  a\
-Xms${es_Xms}\n\
-Xmx${es_Xmx}
}" /etc/elasticsearch/jvm.options

  echo "Starting elasticsearch ..."
  systemctl enable --now elasticsearch.service

  # Create search index for zotero-fulltext
  echo "Creating fulltext search index in elasticsearch ..."
  curl -X PUT "http://localhost:9200/item_fulltext_index" -H "Content-Type: application/json" -d '
{
  "settings": {
    "number_of_replicas": 0
  },
  "mappings": {
    "_source": {
      "enabled": false
    },
    "_routing": {
      "required": true
    },
    "dynamic": false,
    "properties": {
      "libraryID": {
        "type": "integer"
      },
      "content": {
        "type": "text"
      }
    }
  }
}'
  echo
}

# Configure MinIO Server and create buckets
configure_minio() {
  mkdir -p /opt/minio/{conf,data}
  useradd -s /sbin/nologin -d /opt/minio minio

  cat <<EOF > /opt/minio/conf/minio.conf
MINIO_VOLUMES="/opt/minio/data"
MINIO_OPTS="--address :${minio_s3_port} --console-address :${minio_ui_port}"
MINIO_ROOT_USER="${minio_root_user}"
MINIO_ROOT_PASSWORD="${minio_root_password}"
MINIO_BROWSER_REDIRECT_URL="${minio_ui_url}"
EOF

  chown -R minio:minio /opt/minio

  # systemd service
  cat <<'EOF' > /etc/systemd/system/minio.service
[Unit]
Description=Minio
Documentation=https://docs.minio.io
Wants=network-online.target
After=network-online.target
AssertFileIsExecutable=/usr/bin/minio

[Service]
WorkingDirectory=/opt/minio

User=minio
Group=minio

EnvironmentFile=-/opt/minio/conf/minio.conf
ExecStartPre=/bin/bash -c "[ -n \"${MINIO_VOLUMES}\" ] || echo \"Variable MINIO_VOLUMES not set in /opt/minio/conf/minio.conf\""

ExecStart=/usr/bin/minio server $MINIO_OPTS $MINIO_VOLUMES 
StandardOutput=journal
StandardError=inherit
# Specifies the maximum file descriptor number that can be opened by this process
LimitNOFILE=65536
# Disable timeout logic and wait until process is stopped
TimeoutStopSec=0
# SIGTERM signal is used to stop Minio
KillSignal=SIGTERM
SendSIGKILL=no
SuccessExitStatus=0
[Install]
WantedBy=multi-user.target
EOF

  systemctl enable --now minio

  # wait for minio to startup
  sleep 2

  # Create minio alias
  mc alias set zotero http://localhost:${minio_s3_port} ${minio_root_user} ${minio_root_password}

  # Create buckets
  echo "Creating MinIO buckets ..."
  mc mb zotero/zotero
  mc mb zotero/zotero-fulltext
}

# Download Zotero sources
download_zotero() {
  # get latest released version of web-library
  web_library_version=$(curl -s https://api.github.com/repos/zotero/web-library/tags | grep '"name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/')

  echo "Cloning Zotero repositories"
  mkdir -p ${install_dir} && cd ${install_dir}
  for service in "${services[@]}"; do
    git_options=$( [[ ${service} == "web-library" ]] && echo "--branch ${web_library_version}" || echo "" )
    git clone ${git_options} --recurse-submodules "https://github.com/zotero/${service}"
  done

  # Clone dataserver submodule
  cd "${install_dir}/dataserver"
  git clone https://github.com/zendframework/zf1.git /tmp/zf1
  mv -f /tmp/zf1/library/Zend/* /var/www/zotero/dataserver/include/Zend
  rm -rf /tmp/zf1

  # Translation Server
  cd "${install_dir}/translation-server"
  git clone --depth=1 "https://github.com/zotero/translators.git" /modules/translators/
}

# Create www database schema
create_www_schema() {
  cat <<'EOF' > ${install_dir}/dataserver/misc/www.sql
--  ***** BEGIN LICENSE BLOCK *****
--
--  This file is part of the Zotero Data Server.
--
--  Copyright © 2017 Center for History and New Media
--                   George Mason University, Fairfax, Virginia, USA
--                   http://zotero.org
--
--  This program is free software: you can redistribute it and/or modify
--  it under the terms of the GNU Affero General Public License as published by
--  the Free Software Foundation, either version 3 of the License, or
--  (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU Affero General Public License for more details.
--
--  You should have received a copy of the GNU Affero General Public License
--  along with this program.  If not, see <http://www.gnu.org/licenses/>.
--
--  ***** END LICENSE BLOCK *****

CREATE TABLE IF NOT EXISTS `users` (
  `userID` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(255) CHARACTER SET utf8 NOT NULL,
  `password` varchar(255) COLLATE utf8_bin NOT NULL,
  `role` enum('normal','deleted') NOT NULL DEFAULT 'normal',
  PRIMARY KEY (`userID`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS `users_email` (
  `emailID` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `userID` int(10) unsigned NOT NULL,
  `email` varchar(100) CHARACTER SET utf8 NOT NULL,
  `validated` TINYINT(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`emailID`),
  KEY `userID` (`userID`),
  KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS `GDN_User` (
  `userID` int(10) unsigned NOT NULL,
  `Banned` int(1) NOT NULL DEFAULT '0',
  KEY `userID` (`userID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `LUM_User` (
  `UserID` int(10) NOT NULL AUTO_INCREMENT,
  `RoleID` int(2) NOT NULL DEFAULT '0',
    PRIMARY KEY (`UserID`),
  KEY `user_role` (`RoleID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `storage_institutions` (
  `institutionID` smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  `domain` varchar(100) NOT NULL,
  `domainBlacklist` text,
  `storageQuota` int(11) NOT NULL,
  PRIMARY KEY (`institutionID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `storage_institution_email` (
  `institutionID` smallint(5) unsigned NOT NULL,
  `email` varchar(255) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`institutionID`,`email`),
  KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS `users_meta` (
  `userID` mediumint(8) unsigned NOT NULL,
  `metaKey` varchar(60) CHARACTER SET utf8 NOT NULL,
  `metaValue` text CHARACTER SET utf8 NOT NULL,
  `lastUpdated` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`userID`,`metaKey`),
  KEY `metaKey` (`metaKey`,`metaValue`(20))
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;
EOF
}

initialize_database() {
  ## Setup database
  mysql -e "CREATE DATABASE zotero_master;"
  mysql -e "CREATE DATABASE zotero_shard_1;"
  mysql -e "CREATE DATABASE zotero_shard_2;"
  mysql -e "CREATE DATABASE zotero_ids;"
  mysql -e "CREATE DATABASE zotero_www;"

  # Load in master schema
  mysql zotero_master < ${install_dir}/dataserver/misc/master.sql
  mysql zotero_master < ${install_dir}/dataserver/misc/coredata.sql
  mysql zotero_master < ${install_dir}/dataserver/misc/fulltext.sql

  # Load in shard schema
  mysql zotero_shard_1 < ${install_dir}/dataserver/misc/shard.sql
  mysql zotero_shard_1 < ${install_dir}/dataserver/misc/triggers.sql
  mysql zotero_shard_2 < ${install_dir}/dataserver/misc/shard.sql
  mysql zotero_shard_2 < ${install_dir}/dataserver/misc/triggers.sql

  # Load in schema on id servers
  mysql zotero_ids < ${install_dir}/dataserver/misc/ids.sql

  # Load in www schema
  mysql zotero_www < ${install_dir}/dataserver/misc/www.sql

  # Set up shard info
  mysql -e "INSERT INTO zotero_master.shardHosts (shardHostID, address, port, state) VALUES (1, 'localhost', 3306, 'up');"
  mysql -e "INSERT INTO zotero_master.shards (shardID, shardHostID, db, state) VALUES (1, 1, 'zotero_shard_1', 'up');"
  mysql -e "INSERT INTO zotero_master.shards (shardID, shardHostID, db, state) VALUES (2, 1, 'zotero_shard_2', 'up');"

  # Initial users and groups for tests
  mysql -e "INSERT INTO zotero_master.libraries (libraryID, libraryType, shardID) VALUES (1, 'user', 1);"
  mysql -e "INSERT INTO zotero_master.libraries (libraryID, libraryType, shardID) VALUES (2, 'group', 2);"
  mysql -e "INSERT INTO zotero_master.users (userID, libraryID, username) VALUES (1, 1, 'admin');"
  mysql -e "INSERT INTO zotero_master.\`groups\`(groupID, libraryID, name, slug, libraryEditing, libraryReading, fileEditing, description, url) VALUES (1, 2, 'Shared', 'shared', 'admins', 'all', 'members', '', '');"
  mysql -e "INSERT INTO zotero_master.groupUsers (groupID, userID, role) VALUES (1, 1, 'owner');"

  mysql -e "INSERT INTO zotero_shard_1.shardLibraries (libraryID, libraryType) VALUES (1, 'user');"
  mysql -e "INSERT INTO zotero_shard_2.shardLibraries (libraryID, libraryType) VALUES (2, 'group');"

  mysql -e "INSERT INTO zotero_www.storage_institutions (institutionID, domain, storageQuota) VALUES (1, '${domain}', 1000000);"
  mysql -e "INSERT INTO zotero_www.storage_institution_email (institutionID, email) VALUES (1, 'user_name@${domain}');"

  # create first user account
  mysql -e "INSERT INTO zotero_www.users (userID, username, password) VALUES (1, '${user_name}', MD5('${user_password}'));"
  mysql -e "INSERT INTO zotero_www.users_email (userID, email) VALUES (1, '${user_name}@${domain}');"

  # Create zotero database user
  mysql -e "CREATE USER '${zotero_mysql_user}'@'localhost' IDENTIFIED BY '${zotero_mysql_password}';"
  mysql -e "GRANT ALL PRIVILEGES ON zotero_master.* TO '${zotero_mysql_user}'@'localhost';"
  mysql -e "GRANT ALL PRIVILEGES ON zotero_shard_1.* TO '${zotero_mysql_user}'@'localhost';"
  mysql -e "GRANT ALL PRIVILEGES ON zotero_shard_2.* TO '${zotero_mysql_user}'@'localhost';"
  mysql -e "GRANT ALL PRIVILEGES ON zotero_ids.* TO '${zotero_mysql_user}'@'localhost';"
  mysql -e "GRANT ALL PRIVILEGES ON zotero_www.* TO '${zotero_mysql_user}'@'localhost';"
  mysql -e "FLUSH PRIVILEGES;"

  # Change MySQL root password
  mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY '${mysql_root_password}';"
}


configure_dataserver() {
  # Patch Dataserver
  cd "${install_dir}/dataserver"

  chown -R www-data: /var/www/ /var/log/apache2
  chmod -R 775 tmp

  # install dependencies
  sudo -u www-data composer install

  # make patches
  cp include/config/config.inc.php-sample include/config/config.inc.php
  cp include/config/dbconnect.inc.php-sample include/config/dbconnect.inc.php

  sed -i "s#\$TESTING_SITE = .*#\$TESTING_SITE = false;#g" include/config/config.inc.php
  sed -i "s#\$DEV_SITE = .*#\$DEV_SITE = false;#g" include/config/config.inc.php
  sed -i "s#\$DEBUG_LOG = .*#\$DEBUG_LOG = false;#g" include/config/config.inc.php

  sed -i "s#\$BASE_URI = '[^']*'#\$BASE_URI = '${base_uri}'#g" include/config/config.inc.php
  sed -i "s#\$API_BASE_URI = '[^']*'#\$API_BASE_URI = '${api_url}'#g" include/config/config.inc.php
  sed -i "s#\$WWW_BASE_URI = '[^']*'#\$WWW_BASE_URI = '${base_uri}'#g" include/config/config.inc.php

  sed -i "s#\$zotero_auth_salt = ''#\$zotero_auth_salt = '${zotero_auth_salt}'#g" include/config/config.inc.php
  sed -i "s#\$API_SUPER_USERNAME = ''#\$API_SUPER_USERNAME = '${api_super_user}'#g" include/config/config.inc.php
  sed -i "s#\$zotero_api_super_password = ''#\$zotero_api_super_password = '${zotero_api_super_password}'#g" include/config/config.inc.php

  sed -i "s#\$AWS_REGION = ''#\$AWS_REGION = '${aws_s3_region}'#g" include/config/config.inc.php
  sed -i "s#\$AWS_ACCESS_KEY = ''#\$AWS_ACCESS_KEY = '${minio_root_user}'#g" include/config/config.inc.php
  sed -i "s#\$AWS_SECRET_KEY = ''#\$AWS_SECRET_KEY = '${minio_root_password}'#g" include/config/config.inc.php
  sed -i "/S3_BUCKET = '.*/i \\\tpublic static \$S3_ENDPOINT = 'http://localhost:${minio_s3_port}';" include/config/config.inc.php
  sed -i "s#\$S3_BUCKET = ''#\$S3_BUCKET = 'zotero'#g" include/config/config.inc.php
  sed -i "s#\$S3_BUCKET_FULLTEXT = ''#\$S3_BUCKET_FULLTEXT = 'zotero-fulltext'#g" include/config/config.inc.php

  sed -i "s#'redis1.localdomain:6379'#'localhost'#g" include/config/config.inc.php
  sed -i "s#'redis-transient.localdomain:6379'#'localhost'#g" include/config/config.inc.php
  sed -i "s#'memcached1.localdomain:11211:2', 'memcached2.localdomain:11211:1'#'localhost:11211:1'#g" include/config/config.inc.php
  sed -i "s#translation1.localdomain#localhost#g" include/config/config.inc.php
  sed -i "s#\$SEARCH_HOSTS = \[''\]#\$SEARCH_HOSTS = \['localhost'\]#g" include/config/config.inc.php
  sed -i "s#\$ATTACHMENT_PROXY_URL = \"[^\"]*\"#\$ATTACHMENT_PROXY_URL = \"${attachment_proxy_uri}\"#g" include/config/config.inc.php
  sed -i "s#\$HTMLCLEAN_SERVER_URL = '[^']*'#\$HTMLCLEAN_SERVER_URL = 'http://localhost:${htmlclean_server_port}'#g" include/config/config.inc.php

  # remove 'type' from search query (deprecated in elasticsearch version 7.x)
  sed -i "/'type' => self::\$elasticsearchType,/d" model/FullText.inc.php

  # Database configuration
  sed -i "/\$replicas = \[/,/];/d" include/config/dbconnect.inc.php
  sed -i "s#\$host = .*#\$host = 'localhost';#g" include/config/dbconnect.inc.php
  sed -i "s#\$port = .*#\$port = 3306;#g" include/config/dbconnect.inc.php
  sed -i "s#\$user = ''#\$user = '${zotero_mysql_user}'#g" include/config/dbconnect.inc.php
  sed -i "s#\$pass = ''#\$pass = '${zotero_mysql_password}'#g" include/config/dbconnect.inc.php

  sed -zi 's/\(if\s*(\$db\s*==\s*'\''master'\'')\s*{[^}]*\$db\s*=\s*\)[^;]*/\1'\''zotero_master'\''/' include/config/dbconnect.inc.php
  sed -zi 's/\(if\s*(\$db\s*==\s*'\''id1'\'')\s*{[^}]*\$db\s*=\s*\)[^;]*/\1'\''zotero_ids'\''/' include/config/dbconnect.inc.php
  sed -zi 's/\(if\s*(\$db\s*==\s*'\''id2'\'')\s*{[^}]*\$db\s*=\s*\)[^;]*/\1'\''zotero_ids'\''/' include/config/dbconnect.inc.php
  sed -zi 's/\(if\s*(\$db\s*==\s*'\''www1'\'')\s*{[^}]*\$db\s*=\s*\)[^;]*/\1'\''zotero_www'\''/' include/config/dbconnect.inc.php
  sed -zi 's/\(if\s*(\$db\s*==\s*'\''www2'\'')\s*{[^}]*\$db\s*=\s*\)[^;]*/\1'\''zotero_www'\''/' include/config/dbconnect.inc.php
  sed -zi 's/\(if\s*(\$db\s*==\s*'\''shard'\'')\s*{[^}]*\$db\s*=\s*\)[^;]*/\1'\''zotero_shard_1'\''/' include/config/dbconnect.inc.php

  # Change S3 endpoint to custom S3_ENDPOINT
  sed -i "s#'s3.amazonaws.com'#Z_CONFIG::\$S3_ENDPOINT#g" include/Zend/Service/Amazon/S3.php
  sed -i "s#'http://'.self::S3_ENDPOINT#self::S3_ENDPOINT#g" include/Zend/Service/Amazon/S3.php
  sed -i 's#"https://" . Z_CONFIG::\$S3_BUCKET . ".s3.amazonaws.com/"#Z_CONFIG::\$S3_ENDPOINT . "/" . Z_CONFIG::\$S3_BUCKET . "/"#g' model/Storage.inc.php
  sed -i "s#\$awsConfig = \[#\$awsConfig = \['endpoint' => Z_CONFIG::\$S3_ENDPOINT,#g" include/header.inc.php
  sed -i "s#parent::__construct(\$args)#\$args\['use_path_style_endpoint'\] = true;parent::__construct(\$args)#g" vendor/aws/aws-sdk-php/src/S3/S3Client.php

  # Delete objects from S3 bucket when they are deleted from library
  sed -i '/isStoredFileAttachment/,/}/{s/}/ \
				\/\/ Delete attachment from S3 bucket \
				if($info) \{ \
					$s3Client = Z_Core::$AWS->createS3(); \
					$start = microtime(true); \
					$s3Client->deleteObject([ \
						"Bucket" => Z_CONFIG::$S3_BUCKET, \
						"Key" => $info["hash"] \
					]); \
					StatsD::timing("s3.delete", (microtime(true) - $start) * 1000); \
				\} \
			\}/
}' model/DataObjects.inc.php

  export SCHEMA=${install_dir}/dataserver/htdocs/zotero-schema/schema.json
  if [ ! -f ${SCHEMA}.gz -o ${SCHEMA} -nt ${SCHEMA}.gz ]; then
    cat ${SCHEMA} | gzip -c > ${SCHEMA}.gz
  fi

  # create www.sql schema
  create_www_schema

  # Initialiaze database
  initialize_database

  # Run schema updates
  cd ${install_dir}/dataserver/admin
  sudo -u www-data ./schema_update  
}

configure_stream_server() {
  cd "${install_dir}/stream-server"

  sed -i "s#httpPort: .*#httpPort: ${stream_server_port},#g" ./config/default.js
  sed -i "s#apiURL: .*#apiURL: 'http://localhost:${api_port}/',#g" ./config/default.js
  sed -i "/redis: {/,/}/s/host: .*/url: 'redis:\/\/localhost:6379',/g" ./config/default.js
  sed -i "s#trustedProxies: .*#trustedProxies: ['127.0.0.1'],#g" ./config/default.js
}

configure_attachment_proxy() {
  cd "${install_dir}/attachment-proxy"
  mkdir ./tmp && chmod 775 ./tmp

  # Setup configuration
  cp config/sample-config.js config/default.js

  sed -i "/s3: {/,/},/c\
	s3: {\
		endpoint: \"http://localhost:${minio_s3_port}\",\
		bucket: \"zotero\",\
		region: \"${aws_s3_region}\",\
		accessKeyId: \"${minio_root_user}\",\
		secretAccessKey: \"${minio_root_password}\",\
		s3ForcePathStyle: true\
	}," config/default.js

  # Adapt code for MinIO
  sed -i "/this.s3Client = new S3Client({/,/});/c\
	this.s3Client = new S3Client({\
		region: options.config.region,\
		endpoint: options.config.endpoint,\
		forcePathStyle: options.config.s3ForcePathStyle,\
		credentials: {\
			accessKeyId: options.config.accessKeyId,\
			secretAccessKey: options.config.secretAccessKey\
		}\
	});" storage.js
}

configure_full_text_indexer() {
  cd "${install_dir}/full-text-indexer"

  # Fix dependencies
  sed -i '/"version":/a\  "type": "module",' package.json
  sed -i 's/"main": *"index\.js"/"main": "index.mjs"/' package.json
  sed -i '/"scripts": *{/{n; s/.*/    "start": "node server.mjs",\n&/}' package.json

  sed -i '/"dependencies": {/,/}/c\
  "dependencies": {\
    "@aws-sdk/client-s3": "^3.300.0",\
    "@aws-sdk/client-lambda": "^3.300.0",\
    "@aws-sdk/client-sqs": "^3.300.0",\
    "@elastic/elasticsearch": "^8.10.0",\
    "config": "^3.3.9"\
  }' package.json

  # Create configuration file
  cat << EOF > ./config/default.json
{
  "aws": {
    "region": "${aws_s3_region}",
    "endpoint": "http://localhost:${minio_s3_port}",
    "accessKey": "${minio_root_user}",
    "secretKey": "${minio_root_password}"
  },
  "es": {
    "host": "http://localhost:9200",
    "index": "item_fulltext_index"
  },
  "server": {
    "port": "${fulltext_indexer_port}"
  }
}
EOF

  # Adapt for MinIO
  sed -i '/const s3Client = new S3Client();/c\
const s3Client = new S3Client({\
  region: config.get('\''aws.region'\''),\
  endpoint: config.get('\''aws.endpoint'\''),\
  credentials: {\
    accessKeyId: config.get('\''aws.accessKey'\''),\
    secretAccessKey: config.get('\''aws.secretKey'\'')\
  },\
  forcePathStyle: true\
});' index.mjs

  # Create server script
  cat <<'EOF' > server.mjs
import { s3 as s3Handler } from './index.mjs';
import http from 'http';
import config from 'config';

const listenPort = config.get('server.port');

const server = http.createServer(async (req, res) => {
  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const minioEvent = JSON.parse(body);

        const awsEvent = {
          Records: minioEvent.Records.map(rec => ({
            eventName: rec.eventName.replace(/^s3:/, ''),
            s3: {
              bucket: { name: rec.s3.bucket.name },
              object: {
                key: rec.s3.object.key.replace(/%2F/g, "/"),
                eTag: rec.s3.object.eTag
              }
            }
          }))
        };
        
        await s3Handler(awsEvent);

        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('OK');
      } catch (err) {
        console.error('Error processing event:', err);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Error processing event');
      }
    });
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
});

server.listen(listenPort, () => {
  console.log(`Full Text Indexer listening on http://localhost:${listenPort}`);
});

EOF
}

# Create index.html
create_web_library_html_index() {
  cat << EOF > ${install_dir}/web-library/src/html/index.html
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<title>Zotero Web Library</title>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<link rel="stylesheet" href="/static/web-library/zotero-web-library.css">
		<meta name="apple-mobile-web-app-capable" content="yes">
		<meta name="mobile-web-app-capable" content="yes">
		<meta name="apple-mobile-web-app-status-bar-style" content="default">
		<link rel="manifest" href="/manifest.json">
		<link rel="apple-touch-icon" sizes="192x192" href="/static/web-library/icons/icon-192x192.png">
		<link rel="apple-touch-icon" sizes="512x512" href="/static/web-library/icons/icon-512x512.png">
	</head>
<body>
	<div id="zotero-web-library"></div>
  <script>               
  	if (!localStorage.getItem('zoteroUserInfoJ')) {
			console.log("Not logged in");
			window.location.href = 'login.html';
		}
  </script>
	
	<script type="application/json" id="zotero-web-library-config"></script>
	<script>document.getElementById('zotero-web-library-config').textContent = localStorage.getItem('zoteroUserInfoJ');</script>

	<script type="application/json" id="zotero-web-library-menu-config">
		{
			"desktop": [
				{
					"label": "Logout",
					"class": "logout-button",
					"href": "/logout.html",
					"active": true
				}
			],
			"mobile": [
				{
					"label": "Logout",
					"href": "/logout",
					"active": true
				}
			]
		}
	</script>
	<script src="/static/web-library/zotero-web-library.js"></script>
</body>
</html>

EOF
}

# Create login.html
create_web_library_html_login() {
  cat << EOF > ${install_dir}/web-library/src/html/login.html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<link rel="stylesheet" href="/static/web-library/zotero-web-library.css">
	<meta name="apple-mobile-web-app-capable" content="yes">
	<meta name="mobile-web-app-capable" content="yes">
	<meta name="apple-mobile-web-app-status-bar-style" content="default">
	<link rel="manifest" href="/manifest.json">
	<link rel="apple-touch-icon" sizes="192x192" href="/static/web-library/icons/icon-192x192.png">
	<link rel="apple-touch-icon" sizes="512x512" href="/static/web-library/icons/icon-512x512.png">

	<title>Zotero - Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center; /* Horizontally center the content */
            align-items: center; /* Vertically center the content */
            height: 100vh; /* Full viewport height */
            margin: 0;
			flex-direction: column;
        }

        .header {
            font-size: 40px;
            font-weight: bold;
            color: black; /* Default text color for the rest of the word */
            margin-bottom: 20px; /* Add space between header and form */
        }

        .header::first-letter {
            color: #a3212b; /* Red color for the first letter */
        }

        form {
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            width: 300px;
            text-align: left; /* Ensure form content is left-aligned */
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            text-align: left; /* Ensure the label text is left-aligned */
        }

        input {
            width: 100%;
            padding: 10px;
            margin-bottom: 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }

        button {
            width: 100%;
            padding: 12px;
            background-color: #a3212b; /* Button color */
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
        }

        button:hover {
            background-color: #8f1e24; /* Darker color on hover */
        }

        /* Mobile responsiveness */
        @media (max-width: 500px) {
            form {
                width: 90%;
            }
        }
    </style>
</head>
<body>
  <!-- Header Text -->
  <div class="header">zotero</div>

  <!-- Login Form -->
	<form id="loginForm">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" autocomplete="username" required><br>

        <label for="password">Password</label>
        <input type="password" id="password" name="password" autocomplete="current-password" required><br>

        <button type="submit">Login to Zotero</button>
    </form>
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(event) {
            event.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

 	    const data = {
        username: username,
        password: password,
        name: 'Temporary Zotero Web Client Key',
        access: {
          user: {
            library: true,
            notes:true,
            write:true,
            files:true
            },
          groups: {
            all: {
              library:true,
              write:true}
          }
        }
	    }
	    console.log('body:', JSON.stringify(data))
	    fetch('${api_url}keys', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Zotero-API-Version': 3,
					'Zotero-Schema-Version': 32
				},
				body:JSON.stringify(data)
                })
            .then(response => response.json())
  	    .then(data => {
		    console.log('Success:', data);
		    localStorage.setItem('zoteroUserInfoJ', JSON.stringify({
			    username: data.username,
			    userSlug: data.username,
			    userId: data.userID,
			    realname: '',
			    apiKey: data.key
	    	    }));
			window.location.href = 'index.html';
	    } )
            .catch(error => console.error('Error:', error));

        });
    </script>
</body>
</html>

EOF
}

# Create logout.html
create_web_library_html_logout() {
  cat << EOF > ${install_dir}/web-library/src/html/logout.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Zotero - Logout</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="/static/web-library/zotero-web-library.css">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <link rel="manifest" href="/manifest.json">
    <link rel="apple-touch-icon" sizes="192x192" href="/static/web-library/icons/icon-192x192.png">
    <link rel="apple-touch-icon" sizes="512x512" href="/static/web-library/icons/icon-512x512.png">
</head>
<body>
   <script>
      zoterouserinfo = localStorage.getItem('zoteroUserInfoJ');
      console.log(zoterouserinfo);
      jzui = JSON.parse(zoterouserinfo)
      console.log(jzui)
      const apiKey = jzui['apiKey'];
      console.log(apiKey); 
      fetch('${api_url}keys/current', {
          method: 'DELETE',
          headers: {
              'Zotero-API-Key': apiKey
          }
      })
      .then(response => {
          localStorage.removeItem('zoteroUserInfoJ');
          deleteAllCookies();
          window.location.href = 'login.html';

      })
      .catch(error => console.error('Error:', error));
            
      function deleteAllCookies() {
        var cookies = document.cookie.split(";");

        for (var i = 0; i < cookies.length; i++) {
          var cookie = cookies[i];
          var eqPos = cookie.indexOf("=");
          var name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
          document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT";
        }
      }
    </script>
</body>
</html>

EOF
}


create_web_library_html() {
  # remove all existing html files
  rm ${install_dir}/web-library/src/html/*.html

  create_web_library_html_index
  create_web_library_html_login
  create_web_library_html_logout
}

configure_web_library() {
  cd "${install_dir}/web-library"

  sed -i "/apiAuthorityPart/a \\\tapiScheme: '${protocol}'," src/js/constants/defaults.js

  sed -i s#"apiAuthorityPart:.*$"#"apiAuthorityPart: '${api_authority}',"# src/js/constants/defaults.js
  sed -i s#"export const websiteUrl =.*$"#"export const websiteUrl = '${base_uri}';"# src/js/constants/defaults.js
  sed -i s#"export const streamingApiUrl =.*$"#"export const streamingApiUrl = '${stream_url}';"# src/js/constants/defaults.js

  sed -i s#"http://zotero.org/"#"${base_uri}"# src/js/utils.js
  sed -i s#"https?://zotero.org/"#"${base_uri}"# src/js/utils.js

  ## Generate HTML pages: index.html, login.html, logout.html
  create_web_library_html
}


# Install all zotero node.js services (all except dataserver)
install_node_js_service() {
  for ((i=1; i<${#services[@]}; i++)); do
    service="${services[$i]}"
    echo "Installing ${service}"
    run_command=$( [[ ${service} == "web-library" ]] && echo "run serve" || echo "start" )
    
    cd "${install_dir}/${service}"
    npm install

    # additional build step for web-library
    [[ ${service} == "web-library" ]] && npm run build:fetch-or-build-modules && npm run build

    # create systemd service
    cat <<EOF > "/etc/systemd/system/zotero-${service}.service"
[Unit]
Description=Zotero ${service}
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/bin/npm ${run_command}
WorkingDirectory=${install_dir}/${service}
Restart=always
User=www-data
Group=www-data
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

  systemctl enable --now zotero-${service}.service
  done

  # wait for full-text-indexer to startup
  sleep 3
}

generate_ssl_certificates() {
  # generate ssl config
  cat << EOF > /etc/ssl/zotero.conf
[ req ]
default_bits        = 2048
default_keyfile     = zotero.key
distinguished_name  = zotero
prompt              = no
encrypt_key         = no
req_extensions      = v3_req

[ zotero ]
C  = US
ST = Kentucky
L  = Lexington
O  = Self Hosted Zotero
CN = ${domain}
emailAddress = admin@${domain}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = $(hostname -I | awk '{print $1}')
EOF

  # Create directories if they don't exist
  mkdir -p /etc/ssl/certs /etc/ssl/private

  # Generate private key and csr
  openssl req -new -config /etc/ssl/zotero.conf -extensions v3_req -keyout /etc/ssl/private/zotero.key -out /etc/ssl/certs/zotero.csr

  # Generate self-signed certificate
  openssl x509 -req -days 3650 -extensions v3_req -extfile /etc/ssl/zotero.conf -signkey /etc/ssl/private/zotero.key -in /etc/ssl/certs/zotero.csr -out /etc/ssl/certs/zotero.crt

  # Generate Firefox cert_override.txt file
  fingerprint=$(openssl x509 -in /etc/ssl/certs/zotero.crt -noout -fingerprint -sha256 | cut -d= -f2)

  # OID for sha256WithRSAEncryption
  oid="OID.2.16.840.1.101.3.4.2.1"

  cert_override=$(cat <<EOF
# PSM Certificate Override Settings file
# This is a generated file!  Do not edit.
${domain}:443:	${oid}	${fingerprint} 
EOF
  )
}

# Setup Apache2, Enable the new virtualhost and Override gzip configuration
create_apache_config() {
  # Enable Port 8080
  sed -i "/Listen 80/a Listen ${api_port}" /etc/apache2/ports.conf

  apache_logs_dir="/var/log/apache2/zotero"
  mkdir -p ${apache_logs_dir} && chown www-data: ${apache_logs_dir}

  # VirtualHost
  cat << EOF > /etc/apache2/sites-available/zotero.conf
# Main Server / Reverse Proxy
<VirtualHost *:80>
    ErrorLog ${apache_logs_dir}/http-error.log
    CustomLog ${apache_logs_dir}/http-access.log combined

    RewriteEngine On
    ProxyPreserveHost On

    ## Websockets
    # MinIO Websocket
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/minio/(.*)$ ws://localhost:${minio_ui_port}/\$1 [P,L]

    # Zotero Websocket
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/(.*) ws://localhost:${stream_server_port}/\$1 [P,L]

    # Force trailing slashes for
    RewriteCond %{REQUEST_URI} ^/minio$ 
    RewriteRule ^(.*)$ /minio/ [R=301,L]

    # MinIO UI
    RewriteRule ^/minio/(.*)$ http://localhost:${minio_ui_port}/\$1 [P,L]
    ProxyPassReverse /minio/ http://localhost:${minio_ui_port}/

    # Dataserver
    RewriteRule ^/api/(.*)$ http://localhost:${api_port}/\$1 [P,L]
    ProxyPassReverse /api/ http://localhost:${api_port}/

    # Attachments Proxy
    RewriteRule ^/fs/(.*)$ http://localhost:${attachment_proxy_port}/\$1 [P,L]
    ProxyPassReverse /fs/ http://localhost:${attachment_proxy_port}/

    # Web Library
    ProxyPass / http://localhost:${web_library_port}/
    ProxyPassReverse / http://localhost:${web_library_port}/
</VirtualHost>

# Dataserver
<VirtualHost *:${api_port}>
    ErrorLog ${apache_logs_dir}/dataserver-error.log
    CustomLog ${apache_logs_dir}/dataserver-access.log combined

    DocumentRoot ${install_dir}/dataserver/htdocs

    <Directory ${install_dir}/dataserver/htdocs>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>

EOF
 
# Gzip configuration
  cat <<'EOF' > /etc/apache2/conf-available/gzip.conf
<IfModule mod_deflate.c>
    SetOutputFilter DEFLATE
    SetEnvIfNoCase Request_URI .(?:exe|t?gz|zip|iso|tar|bz2|sit|rar) no-gzip dont-vary
    SetEnvIfNoCase Request_URI .(?:gif|jpe?g|jpg|ico|png)  no-gzip dont-vary
    SetEnvIfNoCase Request_URI .pdf no-gzip dont-vary
    #Header append Vary User-Agent env=!dont-vary
</IfModule>

EOF

  a2dissite 000-default
  a2enconf gzip
  a2enmod rewrite headers setenvif proxy proxy_http proxy_wstunnel
  a2ensite zotero

  # Only create https site if https was selected as protocol
  if [[ ${protocol} == "https" ]]; then
    cat << EOF > /etc/apache2/sites-available/zotero-https.conf
<VirtualHost *:443>
    ErrorLog ${apache_logs_dir}/https-error.log
    CustomLog ${apache_logs_dir}/https-access.log combined

    ServerName ${domain}

    SSLEngine on
    RewriteEngine On
    ProxyPreserveHost On

    SSLCertificateFile /etc/ssl/certs/zotero.crt
    SSLCertificateKeyFile /etc/ssl/private/zotero.key

    SSLCipherSuite HIGH:!aNULL:!MD5
    SSLProtocol all -SSLv2 -SSLv3

    # Force trailing slash for /minio
    RewriteCond %{REQUEST_URI} ^/minio$ 
    RewriteRule ^(.*)$ /minio/ [R=301,L]

    # MinIO UI WebSocket
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/minio/(.*)$ ws://localhost:${minio_ui_port}/\$1 [P,L]

    # Zotero Websocket
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/(.*) ws://localhost:${stream_server_port}/\$1 [P,L]

    # Proxy all other requests to port 80
    ProxyPass / http://localhost:80/
    ProxyPassReverse / http://localhost:80/
</VirtualHost>
EOF

    a2enmod ssl
    a2ensite zotero-https
  fi

  # fix permissions
  chown -R www-data: ${install_dir} /var/log/apache2

  # reload apache
  systemctl reload-or-restart apache2
}

# Setup MinIO S3 notifications to full-text-indexer for indexing in elasticsearch
create_fulltext_s3_notifications() {
  mc admin config set zotero notify_webhook:full-text-indexer endpoint="http://localhost:${fulltext_indexer_port}"

  # restart minio and wait for it to startup
  mc admin service restart zotero
  sleep 2

  mc event add zotero/zotero-fulltext arn:minio:sqs::full-text-indexer:webhook --event put,delete
}


### Extras ###
# 1. Linux Debian/Ubuntu Desktop Client Patch Script
generate_linux_client_patch_script() {
  cat << EOF > "${scripts_dir}/patch_zotero_desktop.sh"
#!/bin/bash
# Zotero Ubuntu/Debian Desktop Client Patch Bash Script

# URLs of self-hosted zotero server
base_uri=$base_uri
api_url=$api_url
stream_url=$stream_url

# Self signed certificate override
cert_override="$(cat <<EOT
$cert_override
EOT
)"

# Zotero profile and installation directory
user_home=\$(eval echo "~\${SUDO_USER}")
profile_dir=\$(find \$user_home/.zotero/zotero -maxdepth 1 -type d -name "*.default" | head -n 1)
install_dir=/usr/lib/zotero
omni_dir=/tmp/omni
omni_ja=\${install_dir}/app/omni.ja

# Check if omni.ja file exists
[ ! -f "\$omni_ja" ] && { echo -e "Error: Unable to find omni.ja at: \$omni_ja\nPlease update the value of 'install_dir' in the script and run again"; exit 1; }

# Check if zoteo profile directory exists
[ -z "\$profile_dir" ] && { echo -e "Error: Zotero profile directory does not exist.\nPlease launch Zotero once and exit to let it create profile directory"; exit 1; }

# Check if running as root
if [[ \$EUID -ne 0 ]]; then
  echo "This script needs to be run as root. Re-running with sudo..."
  exec sudo "\$0" "\$@"
fi

# Install dependencies
required=(zip unzip)
missing=()

# Make a list of missing packages
for pkg in "\${required[@]}"; do
  dpkg -s "\$pkg" >/dev/null 2>&1 || missing+=("\$pkg");
done

# Install missing dependencies
if [[ \${#missing[@]} -gt 0 ]]; then
  apt update && apt install -y "\${missing[@]}" || {
    echo "Failed to install one or more packages." >&2
    exit 1
  }
fi

# Backup original omni.ja
make_backup=1
echo "1/5 Backuping up omni.ja"
if [ -f "\$omni_ja.bak" ]; then
    read -p "Overwrite previous backup? (y/N) " response
    if ! [[ "\$response" =~ ^[Yy] ]]; then
      echo "Backup skipped!"
      make_backup=0
    else
      echo "Overwriting previous backup!"
    fi
fi

if [ "\$make_backup" -eq 1 ]; then cp -f "\$omni_ja" "\$omni_ja.bak" || { echo "Backup failed!"; exit 1; } ; fi

# Patch the omni.ja file
echo "2/5 Extracting omni.ja to \${omni_dir}"
rm -rf /tmp/omni && mkdir -p /tmp/omni
unzip -q "\$omni_ja" -d /tmp/omni || { echo "Unzip failed!"; exit 1; }
cd /tmp/omni || { echo "Failed to enter /tmp/omni directory!"; exit 1; }

# Make sure all the URLs exist in the file before attempting to patch
for url in BASE_URI WWW_BASE_URL API_URL STREAMING_URL; do
  grep -q "\$url\: '[^']*'" ./resource/config.js || { echo "Cannot find URL: \$url in \${omni_dir}/resource/config.js "; exit 1; }
done

echo "3/5 Patching config.js"
sed -i "s#BASE_URI: '[^']*'#BASE_URI: '\${base_uri}'#" \${omni_dir}/resource/config.js
sed -i "s#WWW_BASE_URL: '[^']*'#WWW_BASE_URL: '\${base_uri}'#" \${omni_dir}/resource/config.js
sed -i "s#API_URL: '[^']*'#API_URL: '\${api_url}'#" \${omni_dir}/resource/config.js
sed -i "s#STREAMING_URL: '[^']*'#STREAMING_URL: '\${stream_url}'#" \${omni_dir}/resource/config.js

# Compress omni directory to omni.ja
echo "4/5 Repacking omni.ja"
# preserve file ownership permissions
owner=\$(stat -c '%u' "\$omni_ja")
group=\$(stat -c '%g' "\$omni_ja")

# Zip omni.ja back
zip -qr "\$omni_ja" . || { echo "Failed to repack omni.ja to \$omni_ja!"; exit 1; }

# Restore omni.ja file ownership
chown "\$owner:\$group" "\$omni_ja"

# Make zotero desktop work with self signed certificates if using HTTPS
if [ -n "\$cert_override" ]; then
  echo "5/5 Installing SSL certificate override for self signed certificates"

  echo "\$cert_override" > \${profile_dir}/cert_override.txt

  # Fix ownership of cert_override.txt
  chown \${SUDO_USER}:\${SUDO_USER} \${profile_dir}/cert_override.txt
fi

# clean up
rm -rf /tmp/omni

echo "Done."

EOF
}

# 2. Windows Desktop Client Patch Script
generate_windows_client_patch_script() {
  cat << EOF > "${scripts_dir}/patch_zotero_desktop.ps1"
# Zotero Windows Desktop Client Patch PowerShell Script
#
# The script requires Elevated Privilege to modify the file in C:\Program Files\Zotero
# To execute this script, follow these steps:
#
#   1. Launch PowerShell
#
#   2. Windows PowerShell prevents execution of scripts by default.
#     Run this command in PowerShell before running the script to allow scripts execution:
#        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
#
#   3. Navigate to the Directory where you save the script
#        cd C:\Users\zotero\Downloads
#
#   4. Execute the script like so:
#        .\patch_zotero_desktop.ps1
#

Add-Type -AssemblyName System.IO.Compression.FileSystem

# URLs of self-hosted zotero server
\$base_uri="$base_uri"
\$api_url="$api_url"
\$stream_url="$stream_url"

# Self signed certificate override
\$cert_override="$(cat <<EOT
$cert_override
EOT
)"

\$install_dir = "C:\Program Files\Zotero"
\$install_dir_alt = [Environment]::GetFolderPath('LocalApplicationData')
\$profile_dir = Join-Path ([Environment]::GetFolderPath("UserProfile")) "AppData\Roaming\Zotero\Zotero\Profiles"
\$omni_dir= Join-Path ([System.IO.Path]::GetTempPath()) "omni"
\$config_file= Join-Path \$omni_dir "resource\config.js"

# Check both potential install directories
if (Test-Path \$install_dir) {
  \$omni_ja = Join-Path \$install_dir "app\omni.ja"
} else {
  \$omni_ja = Join-Path \$install_dir_alt "app\omni.ja"
}

if (-Not (Test-Path \$omni_ja)) {
  Write-Error "Error: Unable to find Zotero install directory. Please update 'install_dir' in the script and run again."
  exit
}

if (-Not (Test-Path \$profile_dir)) {
  Write-Error "Zotero profile directory does not exist. Please launch Zotero once and exit to let it create profile directory"
  exit
}

\$default_profile = Get-ChildItem \$profile_dir -Directory | Where-Object { \$_.Name -like "*.default" } | Select-Object -First 1

if (-Not \$default_profile) {
  Write-Error "Zotero default profile directory does not exist. Please launch Zotero once and exit to let it create profile directory"
  exit
}

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  # Relaunch the script with elevated rights
  \$arguments = "-ExecutionPolicy Bypass -File \`"\$PSCommandPath\`""
  Start-Process powershell -Verb runAs -ArgumentList \$arguments
  exit
}

Write-Output "1/5 Backuping up omni.ja"
\$make_backup = \$true
if (Test-Path "\$omni_ja.bak") {
  \$response = Read-Host "Overwrite previous backup? (y/N)"
  if (-Not (\$response -match '^[Yy]')) {
	  Write-Output "Backup skipped!"
      \$make_backup = \$false
  } else {
	  Write-Output "Overwriting previous backup!"
  }
}

if (\$make_backup) { Copy-Item "\$omni_ja" "\$omni_ja.bak" -Force }

# Extract omni.ja
Write-Output "2/5 Extracting omni.ja to \$omni_dir"
Remove-Item \$omni_dir -Recurse -Force -ErrorAction SilentlyContinue
[System.IO.Compression.ZipFile]::ExtractToDirectory(\$omni_ja, \$omni_dir)

# Check if config.js exists
if (-Not (Test-Path \$config_file)) {
  Write-Error "Error: Unable to find config.js: \$config_file"
  exit 1
}

Write-Output "3/5 Patching config.js"
# Patch the config.js file
(Get-Content \$config_file) \`
  -replace "(BASE_URI:\s*)'[^']*'", "\`\$1'\$base_uri'" \`
  -replace "(WWW_BASE_URL:\s*)'[^']*'", "\`\$1'\$base_uri'" \`
  -replace "(API_URL:\s*)'[^']*'", "\`\$1'\$api_url'" \`
  -replace "(STREAMING_URL:\s*)'[^']*'", "\`\$1'\$stream_url'" \`
    | Set-Content \$config_file

# Repack omni.ja
Write-Output "4/5 Repacking omni.ja"
# Delete previous omni.ja
Remove-Item \$omni_ja -Force

# Compress omni directory to omni.ja
\$zip = [System.IO.Compression.ZipFile]::Open(\$omni_ja, [System.IO.Compression.ZipArchiveMode]::Create)

Get-ChildItem -Recurse -File -Path \$omni_dir | ForEach-Object {
    \$relativePath = \$_.FullName.Substring(\$omni_dir.Length + 1) -replace '\\\\', '/'
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(\$zip, \$_.FullName, \$relativePath) | Out-Null
}

\$zip.Dispose()

# Make Zotero Desktop work with self signed certificates if using HTTPS
if (\$cert_override -ne "") {
  Write-Output "5/5 Installing SSL certificate override for self signed certificates"
  # get the default prfile path
  \$default_profile = Get-ChildItem \$profile_dir -Directory | Where-Object { \$_.Name -like "*.default" } | Select-Object -First 1
  \$cert_override_path = Join-Path \$default_profile.FullName "cert_override.txt"
  \$cert_override | Set-Content -Path \$cert_override_path -Encoding UTF8
}

# Clean up
Remove-Item \$omni_dir -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "Done."

EOF
}

# Show a series of message boxes at completion
show_final_info() {
  whiptail --title "Installation Complete" --msgbox \
  "Please note down the following information since it will not be shown again:

MinIO UI URL        : $minio_ui_url
MinIO username      : $minio_root_user
MinIO password      : $minio_root_password
MySQL root password : $mysql_root_password

" 15 60

  if [[ "$protocol" == "https" ]]; then
    whiptail --title "Reverse Proxy Configuration" --msgbox \
  "If you are planning to use a reverse proxy in front of your installation, point it here:
  
  Proxy Endpoint: http://$(hostname -I | awk '{print $1}'):80

You can skip this step if you want to use the self-signed certificate.
  " 15 60
  fi

  whiptail --title "Zotero Desktop Client Patches" --msgbox \
"Copy scripts from  ${scripts_dir}  to your PC and run to patch official zotero desktop clients.

Linux: sudo ./patch_zotero_desktop.sh

Windows PowerShell (admin): .\patch_zotero_desktop.ps1
" 15 60

  whiptail --title "Windows PowerShell Script Execution" --msgbox \
"Windows PowerShell prevents execution of scripts by default. Run the following command in PowerShell before running the script to allow scripts execution:

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
" 15 60

  whiptail --title "Zotero Desktop Client Download" --msgbox \
"Clink the link below to download Zotero Desktop Client. Install the client, then run the scripts to apply necessary patches.

  Zotero Desktop: https://www.zotero.org/download/

Use the user name and password you created during this install in Zotero Client Settings on Sync tab.
" 15 60

  whiptail --title "Zotero Web Library Login" --msgbox \
"Here is the link to access your Zotero Library in a Web Browser:

  Web Library: $base_uri

Use the same user name and password you created during this install.
" 15 60

  echo "Installation Complete."
}

install_dependencies() {
  install_os_packages
  install_node_js
  install_elasticsearch
  install_minio
}

configure_dependencies() {
  configure_git
  configure_php
  configure_mysql
  configure_elasticsearch
  configure_minio
}

# Configure Zotero services
configure_zotero() {
  configure_dataserver
  configure_stream_server
  configure_attachment_proxy
  configure_full_text_indexer
  configure_web_library
}

## Install Zotero services
install_zotero() {
  # install all node.js services (all except dataserver)
  install_node_js_service

  # Generate self-signed SSL certificates
  [[ ${protocol} == "https" ]] && generate_ssl_certificates

  # create apache VirtualHost sites
  create_apache_config
  
  # Setup S3 notifications from MinIO to full-text-indexer
  create_fulltext_s3_notifications
}

## Generate scripts to patch Zotero desktop clients
generate_client_patch_scripts() {
  echo "Creating scripts to patch Zotero Desktop clients ..."
  mkdir -p "${scripts_dir}"

  generate_linux_client_patch_script
  generate_windows_client_patch_script
}

### Start Here ###
## Check for sudo
[[ $EUID -ne 0 ]] && { echo "This script requires root access; please run with sudo."; exit 1; }

## Collect User Input
collect_user_input

## Install and configure OS packages and other dependencies
install_dependencies
configure_dependencies

## Download, patch, and install zotero services
download_zotero
configure_zotero
install_zotero

### Extras ###
generate_client_patch_scripts

### Done ###
show_final_info
