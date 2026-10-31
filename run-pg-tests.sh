set -eu
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv >/dev/null
python3 -m venv /tmp/testenv
/tmp/testenv/bin/pip install -q -r requirements-week4.txt -r requirements-week5.txt
export PYTHONPATH=src:.
export WEEK4_TEST_PG=1
export PGHOST=postgres
export PGPORT=5432
export PGUSER=soc_owner
export PGDATABASE=soc
export PGPASSWORD="$WEEK5_DB_PASSWORD"
/tmp/testenv/bin/python -m unittest tests.test_week5_psycopg_semantics
