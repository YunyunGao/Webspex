# /usr/bin/env python3

""" Flask based web-App for the AUSPEX software. Version 1.0.

JINJA2 Templates are stored in templates.
"""

import base64
import datetime
import enum
import hashlib
import json
import os
import random
import re
import secrets
import subprocess
import time
from pathlib import Path

import retricon  # identicon generator
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_redis import FlaskRedis
from flask_rq2 import RQ
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename

########################################
# ----- GLOBAL ----------------------- #
########################################


class JobStatus(enum.IntEnum):
    preparing = 0
    queued = 1
    running = 2
    finished = 3
    error = -1
    timeout = -2


_DEFAULT_CONFIG = {
    "JOBDIR": "/data/jobs",
    "MTZDIR": "/data/mtz",
    "AUSPEX": "/home/auspex/miniconda3/envs/auspex/bin/auspex",
    "REDIS_URL": "redis://:@localhost:6379/0",
    "PATHOLOGIES": str(Path(__file__).parent / "pathologies.json"),
    # 96 byte secret used by FLASK to encrypt cookies.
    # Flask store a hash of a random number, time and ip to identify users.
    # Can be generated by: head -c 96 /dev/random | base64
    # Cycling this key will invalidate currently stored user identities
    "COOKIEKEY": (
        "MuxT/Bb7baPPB3QHusY4az3C3rS7AasEjfYn0mItHvw0RjQHcoSg/XLkY4KXVZL4"
        "W8zu9sSbvAavIH9gPoeBeNnt7gtQHB7dX/aC6NrLOuqlk+avN69hFoTbqn1PCAt7"
    ),
    # lifetimes
    "MAX_CONTENT_LENGTH": 256 * 1024 * 1024,  # 256MB
    "JOB_LIFETIME": 3600 * 24 * 7,  # expire after 1 week
    "CLEANDELAY": 3600,  # clean expired jobs every hour
    "SESSION_EXPIRE": 3600 * 24 * 30,  # expire after 30 days
    # domain handling (redirect domains will be redirected to main domain, all others will get 503)
    "MAIN_DOMAIN": "auspex.physnet.uni-hamburg.de", #"134.100.109.233", #"127.0.0.1", #"www.auspex.de",
    "REDIRECT_DOMAINS": [
        "auspex.de",
        "www.auspex.de",
    ],
    # Job limits. (Partially deprecated as NGINX covers most aspects)
    "JOBS_PER_SESSION": 4,
}

# randomize seed, compile pdb/b64 regex
random.seed()
pdbregex = re.compile("^[a-z0-9]{4}$")
b64regex = re.compile("[^A-Za-z0-9-_=]")  # matches all characters NOT found in urlsafe b64

# create main App
app = Flask(__name__)

# load config
app.config.from_mapping(_DEFAULT_CONFIG)
app.config.from_envvar("WEBSPEX_CONFIG", silent=True)

# load secret
app.secret_key = base64.b64decode(app.config["COOKIEKEY"])

# connect to redis database
redis_store = FlaskRedis(app)
redis_queue = RQ(app)

# load pathologies-JSON and ABORT if it can not be opened.
exampleList = json.loads(Path(app.config["PATHOLOGIES"]).read_text())


########################################
# ----- HELPER ----------------------- #
########################################


def enforce_b64(inStr, size=80, fallback=None):
    """If inStr matches base64 criteria (length, regex) then return inStr else return fallback"""
    if len(inStr or "") == size:
        subStr = b64regex.sub("", str(inStr))
        if len(subStr) == size:
            return subStr
    return fallback


def render_generic_error(id_=0, error="undefined"):
    """Return generic error template for given id and error message.

    :param id_: error id.
    :param error: error message.
    :return: Rendered HTML of generic error template for given id/error.
    """
    # time.sleep(2)
    return render_template("error.html", id=id_, error=error)


def check_mtz_file_extension(filename):
    """Simple file extension check.

    :param filename: File name to be checked.
    :return: True if file extension is '.mtz'.
    """
    return Path(filename).suffix.lower() == ".mtz"


def cleanup_mtz(id_):
    """Remove input mtz file in job directory specified by id.

    :param id_: jobID as integer.
    """
    if id_:
        id_ = int(id_)
        mtz_path = Path(app.config["JOBDIR"]) / str(id_) / "input.mtz"
        if mtz_path.is_file():
            print(f"removing old {mtz_path}")
            mtz_path.unlink(missing_ok=True)


def chunkwise_sha512(fname):
    """Calculate sha512 of file chunkwise using 4kb chunks.

    :param fname: Path to file.
    :return: sha512 hash of file.
    """
    hash_sha512 = hashlib.sha512()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha512.update(chunk)
    return hash_sha512.hexdigest()


def out_of_resources():
    """Check file system resources. Returns False if more than 95% are in use."""
    fsys = os.statvfs(app.config["JOBDIR"])
    bytesTotal = fsys.f_frsize * fsys.f_blocks
    bytesFree = fsys.f_frsize * fsys.f_bfree
    return float(bytesFree) / float(bytesTotal) < 0.05


########################################
# ----- SESSIONS --------------------- #
########################################

"""
A short primer on the webspex redis interface
 - Everything is prefixed with 'webspex.' .
 - The following elements/patterns exist:

  > Sessions <String> : "session:<base64 of ident>" = '' with a set lifetime.
  > Jobs     <Hash>   : "job:<int64-id>" = {
        timestamp: <Timestamp>,
        shared:    <boolean shared flag>,
        status:    <See JobStatus Dict>,
        session:   <Session-Ident in base64>,
        options:   <Options as ' ' joined string>,
        name:      <Job Name>
    }

"""


def generate_session_ident():
    """Applies sha3_512 on 64 random bytes and system clock to generate a random session ident.

    :param extra_data: Additional data to use for session ident generation.
    :return: Session ident hash.
    """
    timestamp = time.monotonic_ns()
    prehash = secrets.token_bytes(64) + timestamp.to_bytes(
        1 + timestamp.bit_length() // 8, "big", signed=False
    )
    return hashlib.sha512(prehash).digest()


def get_session_ident(enforceExisting=False):
    """Return or create session ident as base64 encoded string.

    Returns the session identification payload as base64 encoded string.
    If none exists and enforceExisting is false, a new unique ident is generated, stored in the session, and returned.

    :param enforceExisting: If true, no new ident will be generated if it does not already exist.
    :return: Unique session ident as base64 encoded string.
    """
    if "payload" in session:
        id64 = base64.urlsafe_b64encode(session["payload"]).decode()
        key = "webspex.session:" + id64
        if redis_store.exists(key):
            redis_store.expire(key, app.config["SESSION_EXPIRE"])  # update expiration date
            return id64

    if not enforceExisting:
        # no or invalid session ident -> generate new ident
        while True:
            ident = generate_session_ident()
            id64 = base64.urlsafe_b64encode(ident).decode()
            key = "webspex.session:" + id64
            if not redis_store.exists(key):
                redis_store.sadd(key, "+++placeholder+++")
                redis_store.expire(key, app.config["SESSION_EXPIRE"])
                session["payload"] = ident
                return id64
    else:
        return None


def session_add_job(id64, jobID):
    """Add job (jobID) to session (id64) in redis database.

    :param id64: Session ID as base64 encoded string.
    :param jobID: jobID as base64 encoded string."""
    key = "webspex.session:" + id64
    redis_store.sadd(key, enforce_b64(jobID))


def get_session_jobs(id64):
    """Get stored jobs of a session (id64) from redis database or None if the session does not exist.

    :param id64: Session ID as base64 encoded string.
    :return: List of jobIDs as base64 encoded string associated with session or None if session does not exist."""
    if id64:
        key = "webspex.session:" + id64
        if redis_store.exists(key):
            members = [mIt.decode("utf-8") for mIt in redis_store.smembers(key)]
            jobList = [enforce_b64(jIt) for jIt in (members) if enforce_b64(jIt)]
            print(str(jobList))
            return jobList
    return None


def get_session_active_jobs(id64):
    """Return currently active (status is 'queued' or 'running') jobs of a session (id64) as list.

    :param id64: session id as base64 encoded string (PASSED UNCHECKED!).
    :return: List of jobIDs with status='queued'/'running' as base64 encoded strings or None.
    """
    jobList = get_session_jobs(id64)
    if jobList:
        return [
            jIt
            for jIt in jobList
            if jIt and get_job(jIt, keys=("status")) in [JobStatus.queued, JobStatus.running]
        ]
    return None


@app.before_request
def do_before_request():
    """Called before request handling. Redirects REDIRECT_DOMAINS to MAIN_DOMAIN and returns 403 if domain is unknown.
    Also makes session cookie permanent if possible."""

    url = url_parse(request.url)
    if url.host in app.config["REDIRECT_DOMAINS"]:
        return redirect(f"https://{app.config['MAIN_DOMAIN']}/{str(request.path)}")
    elif url.host != app.config["MAIN_DOMAIN"]:
        return abort(403)

    # make browser session permanent
    if get_session_ident(enforceExisting=True):
        session.permanent = True
        app.permanent_session_lifetime = datetime.timedelta(seconds=app.config["SESSION_EXPIRE"])
        session.modified = True


########################################
# ----- JOBS ------------------------- #
########################################


def generate_job_id_and_dir():
    """Apply base64 on 60 random bytes until a unique job-id is generated,
    then create a job directory for the generated id.

    :return: tuple: jobID as base64 encoded string, jobPath as string
    """
    while True:
        job_id = secrets.token_urlsafe(60)  # should be 80 characters long
        job_path = Path(app.config["JOBDIR"]) / job_id
        if not job_path.exists():
            job_path.mkdir(parents=True)
            return job_id, str(job_path)


def get_job_dir(job_id):
    """Return the job directory for the given base64 encoded jobID based on the app.config settings.

    :param job_id: jobID as base64 encoded string.
    :return: path to job directory as string.
    """
    job_dir = Path(app.config["JOBDIR"]).resolve() / job_id
    if job_dir.resolve() != job_dir or job_dir.parent != Path(app.config["JOBDIR"]).resolve():
        print("ALERT: jobID alters path!")
        raise ValueError("jobID invalidates path")
    return job_dir


def new_job(sessionIdent, shared=False, timestamp=None, options=[], name=""):
    """Creates new job for the given session and stores it in redis with the given timestamp, name, and options.

    :param sessionIdent: Associated session ident. Must exist but is not validated.
    :param shared: Boolean: Shared or private job. Defaults to Private.
    :param timestamp: Unix epoch as string. Defaults to time.time().
    :param options: List of strings containing the command line parameters. Defaults to [].
    :param name: Name of the job as string.
    :return: tuple of JobID as base64 encoded string, jobDir as string
    """
    if not timestamp:
        timestamp = str(int(time.time()))
        # print("-> " + timestamp)
    if sessionIdent:
        jobID, jobDir = generate_job_id_and_dir()
        print(
            "Generated job '{}' for ident '{}' with directory '{}'.".format(
                jobID, sessionIdent, jobDir
            )
        )
        redis_store.hmset(
            "webspex.job:" + jobID,
            {
                "timestamp": timestamp,
                "shared": str(int(shared)),
                "status": JobStatus.preparing.value,
                "session": sessionIdent,
                "options": " ".join(options),
                "name": name,
            },
        )
        redis_store.expire("webspex.job:" + jobID, app.config["JOB_LIFETIME"])
        session_add_job(sessionIdent, jobID)
        return jobID, jobDir
    raise ValueError("Invalid session ident.")


def set_job_status(id_, status):
    """Sets status of given job.

    .. warning:: Will create non-exipiring redis entries if non-existant ids are given.

    :param id_: jobID as base64 encoded string
    :param status: Status string (e.g. 'queued').
    """
    redis_store.hset("webspex.job:" + str(id_), "status", JobStatus[status].value)


def enqueue_job(jobID, jOpt=None):
    """Enqueues an existing job to the redis-queue with given options and updates job status.

    :param jobID: jobID as base64 encoded string.
    :param jOpt: command line arguments as list of strings.
    """
    if jOpt is None:
        jOpt = get_job(jobID, keys=("options"))  # query redis db for job-options

    set_job_status(jobID, "queued")
    run_auspex.queue(jobID, jOpt)


def is_job(jobID):
    """Returns true if jobID exists in redis.

    :param jobID: jobID as base64 encoded string.
    :return: True if job exists, otherwise False.
    """
    if jobID:
        return redis_store.exists("webspex.job:" + str(jobID)) > 0
    return False


def get_job(jobID, keys=("timestamp", "shared", "status", "session", "options")):
    """Queries redis for given job and returns job attributes specified in keys as tuple.

    By default returns tuple of (Timestamp, Shared, Status, Session, Options) as (Int, Int, Int, Str, Str).
    ['session', 'options', 'name'] are returned as string, others as integer.

    :param jobID: JobID as base64 encoded string. Raises ValueError if invalid.
    :param keys: Requested job keys/attributes as tuple/iterable. Defaults to ('timestamp', 'shared', 'status', 'session', 'options')
    :return: Requested values as tuple.
    """
    if jobID:
        return [
            x.decode() if k in ["session", "options", "name"] else int(x.decode())
            for k, x in zip(keys, redis_store.hmget("webspex.job:" + str(jobID), *keys))
            if x is not None
        ]

    raise ValueError("Invalid job id.")


def is_job_accessible(jobID, sessionIdent):
    """Returns True if: 1) The job exists AND 2) The job is owned by the session OR is shared.

    :param jobID: jobID as base64 encoded string.
    :param sessionIdent: session identifier as base64 encoded string.
    :return: True if job exists AND is either owned by the session or shared and thus accessible.
    """
    try:
        jShared, jSession = get_job(jobID, keys=("shared", "session"))
        if jShared == 1 or (
            jSession == sessionIdent and redis_store.exists("webspex.session:" + sessionIdent)
        ):
            return True
    except ValueError as e:
        # print("ve!")
        pass
    return False


def generate_job_identicon(jobID):
    """Generate and 'identicon' (small easily recognizable image) of the sha512 of the input.mtz for a job and store it as 'hash.png' in the job directory.

    :param jobID: jobID as base64 encoded string.
    """
    jobDir = get_job_dir(jobID)
    hash = chunkwise_sha512(os.path.join(jobDir, "input.mtz"))
    image = retricon.retricon(hash, width=96, style="github")
    image.save(os.path.join(jobDir, "hash.png"))


########################################
# ----- QUEUE ------------------------ #
########################################


@redis_queue.job
def run_auspex(id_, opt=[]):
    """Called by redis-queue-worker (rqworker.service). Runs AUSPEX for the given JobID using the given command line options.

    :param id_: jobID as base64 encoded string.
    :param opt: List of strings representing command line options.
    """
    try:
        # generate auspex arguments and command line
        dir_ = get_job_dir(id_)
        opt += ["--single-figure", "--no-individual", "--no-filename-in-title"]
        cmd_line = [app.config["AUSPEX"]] + opt + ["input.mtz"]

        # open output log
        outf = open(os.path.join(dir_, "auspex.log"), "w")

        # start subprocess
        set_job_status(id_, "running")
        return_code = subprocess.call(
            cmd_line, stdin=subprocess.DEVNULL, stdout=outf, stderr=outf, shell=False, cwd=dir_
        )

        # stop subprocess
        print(return_code)
        outf.close()

        # check return code and raise RunTime error on failure
        if return_code != 0:
            raise RuntimeError(f"Return code {return_code}")
        else:
            set_job_status(id_, "finished")

    except Exception as e:
        print(f"Execution failed: '{e}'")
        # Adjust job status on any error
        set_job_status(id_, "error")


@redis_queue.exception_handler
def except_in_auspex(jobObj, exec_info):
    """Exception handler for redis queue."""
    print(str(exec_info))


########################################
# ----- ROUTES ----------------------- #
########################################

# ABOUT
@app.route("/")
def index():
    """Index: Starting page. Render index.html"""
    return render_template("index.html")


# UPLOAD FORM
@app.route("/upform/")
def upform():
    """
    Upload form for MTZ files or select PDB codes to be analyzed.
    Renders upform.html if session exists or legal-dsgvo.html disclaimer if no cookie/session was set.
    Possible errors: out of resources, out of jobs per session
    """
    if out_of_resources():
        return redirect(url_for("error_resources"))

    sessIdent = get_session_ident(enforceExisting=True)
    if sessIdent:
        # return redirect(url_for('error_outofjobs'))
        activeJobList = get_session_active_jobs(sessIdent)
        if activeJobList and len(activeJobList) > app.config["JOBS_PER_SESSION"]:
            return redirect(url_for("/error/outofjobs"))
        else:
            return render_template("upform.html")
    else:
        return render_template("legal-dsgvo.html")


# PATHOLOGIES
@app.route("/pathol/")
def pathol():
    """Pathology showcase. Render pathol.html with exampleList from pathologies.json as exList."""
    return render_template("pathol.html", exList=exampleList)


# LEGAL NOTICE / "IMPRESSUM"
@app.route("/legal/")
def legal():
    """Legal notice of ownership. German 'IMPRESSUM'. Renders legal.html."""
    return render_template("legal.html")


# DSGVO COOKIE REQUEST
@app.route("/dsgvo/")
def dsgvo():
    """
    DSGVO Cookie request. Redirected to upon clicking 'ACCEPT' on legal-dsgvo.html.
    Creates session ident, stores it as cookie and redirects to upform.
    Referer MUST be local MAIN_DOMAIN or REDIRECT_DOMAINS (prevents external auto-accept by link!).
    """
    # validate referrer
    if request.referrer and url_parse(request.referrer).host in [
        app.config["MAIN_DOMAIN"],
        *app.config["REDIRECT_DOMAINS"],
    ]:
        get_session_ident()
        return redirect(url_for("upform"))

    # TODO: If no unexpected errors and behaviour occurs, exchange this with a redirect to /upform/.
    # TODO: A direct redirect without an error could create an infinite loop, which is why this must be checked first.
    print(f"Warning, unexpected referrer: '{request.referrer}'!")
    return render_generic_error(
        60, f"Invalid referrer. Link to {app.config['MAIN_DOMAIN']}/upform/ instead."
    )


# RUN-AUSPEX
@app.route("/auspex/", methods=["POST"])
@app.route("/auspex/<redoJobID>", methods=["POST"])
def auspex(redoJobID=None):
    """AUSPEX job run and rerun request. Arguments sent by POST."""
    if out_of_resources():
        return redirect(url_for("/error/resources"))

    sessIdent = get_session_ident(enforceExisting=True)
    if sessIdent:  # enforce existing session ident

        # enforce queued job limit
        activeJobList = get_session_active_jobs(sessIdent)
        if activeJobList and len(activeJobList) > app.config["JOBS_PER_SESSION"]:
            return redirect(url_for("/error/outofjobs"))

        elif request.method == "POST":  # enforce POST-data
            options = []
            shared = False

            # validate options from  POST options object
            if "res" in request.form and request.form["res"] != "":
                resi = float(request.form["res"])
                if resi < 0 or resi > 200:
                    return render_generic_error(id_=-1, error="Invalid resolution.")
                elif resi != 0 and resi != -float("inf") and resi != float("inf"):
                    options.append("--dmin")
                    options.append(str(resi))

            if "ylim" in request.form:
                ylim = request.form["ylim"]
                if ylim == "minmax":
                    options.append("--ylim")
                    options.append("minmax")
                elif ylim == "auto":
                    options.append("--ylim")
                    options.append("auto")
                elif ylim == "auto_low":
                    options.append("--ylim")
                    options.append("auto_low")
                elif ylim == "low":
                    options.append("--ylim")
                    options.append("low")

            if not ("ice" in request.form):
                options.append("--no-automatic")

            if "shd" in request.form:
                shared = True

            try:
                # check if it is a run or a rerun
                eID = enforce_b64(redoJobID)
                if eID is None:
                    # a new run: is it a PDB code or an MTZ upload?
                    if (
                        "actcode" in request.form
                        and request.form["actcode"] == "true"
                        and "code" in request.form
                    ):

                        # PDB code: Create job, link MTZ file to job directory as input.mtz
                        pdbcode = str(request.form["code"])[0:4].lower()
                        if pdbregex.match(pdbcode):  # validate format
                            mtzPath = os.path.join(
                                app.config["MTZDIR"], pdbcode[1:3], pdbcode + ".mtz"
                            )
                            if os.path.exists(mtzPath) and mtzPath == os.path.abspath(mtzPath):
                                id, jobDir = new_job(
                                    sessIdent, options=options, shared=shared, name=pdbcode.upper()
                                )
                                os.link(
                                    mtzPath, os.path.join(jobDir, "input.mtz")
                                )  # create hardlink
                            else:
                                return render_generic_error(
                                    id_=-1, error="PDB code invalid or missing MTZ data."
                                )
                        else:
                            return render_generic_error(id_=-1, error="PDB code invalid.")

                    elif (
                        "actmtz" in request.form
                        and request.form["actmtz"] == "true"
                        and "file" in request.files
                    ):

                        # MTZ file: Validate file, create job, store file as input.mtz
                        file = request.files["file"]
                        if file and file.filename != "" and check_mtz_file_extension(file.filename):
                            id, jobDir = new_job(
                                sessIdent,
                                options=options,
                                shared=shared,
                                name=secure_filename(file.filename)[0:20],
                            )
                            file.save(os.path.join(jobDir, "input.mtz"))  # save input file
                        else:
                            return render_generic_error(id_=-1, error="Error uploading file.")
                    else:
                        return render_generic_error(id_=-1, error="Invalid action.")

                elif (
                    eID
                    and is_job_accessible(eID, sessIdent)
                    and "actredo" in request.form
                    and request.form["actredo"] == "true"
                ):
                    # a rerun of a previous job: Copy job metadata, create new job, link input.mtz of previous job to new job directory
                    oldJobName = get_job(eID, keys=["name"])
                    if oldJobName:
                        oldJobName = oldJobName[0]
                        splitName = oldJobName.split("#")
                        if splitName[-1] != oldJobName:
                            try:
                                oldJobName = (
                                    "#".join(splitName[:-1]) + "#" + str(int(splitName[-1]) + 1)
                                )
                            except ValueError:
                                oldJobName += "#2"
                        else:
                            oldJobName += "#2"
                    id, jobDir = new_job(sessIdent, options=options, shared=shared, name=oldJobName)
                    oldJobDir = get_job_dir(eID)
                    # print("linking {} to {}".format(os.path.join(oldJobDir, "input.mtz"), os.path.join(jobDir, "input.mtz")))
                    os.link(
                        os.path.join(oldJobDir, "input.mtz"), os.path.join(jobDir, "input.mtz")
                    )  # create hardlink

                else:
                    return render_generic_error(id_=-1, error="Invalid action.")

                # after job creation and input.mtz storage/linkage: Generate identicon and enqueue job to redis-queue.
                generate_job_identicon(id)
                enqueue_job(id, options)

                # redirect to results page for jobID
                return redirect(url_for("results", id=id))

            # Various errors with as little contextual information as possible.
            except ValueError as e:
                return render_generic_error(
                    id_=-2, error="Unable to start job due to internal error."
                )
            except KeyError as e:
                return render_generic_error(
                    id_=-3, error="Unable to start job due to internal error."
                )
            except PermissionError as e:
                return render_generic_error(
                    id_=-4, error="Unable to start job due to internal error."
                )

        else:
            return render_generic_error(id_=-1, error="Invalid method.")
    else:
        return render_generic_error(id_=-1, error="Invalid session.")

    # return render_generic_error(id=-1, error="Unable to start job.")


# AJAX/JSON
@app.route("/ajax/<id>")
def ajax(id):
    """AJAX requests for results of jobID. Returns JSON of job data and job log if job is accessible for given session."""
    sessIdent = get_session_ident(enforceExisting=True)
    eID = enforce_b64(id)
    if eID and is_job_accessible(eID, sessIdent):
        cout = "Starting...\nLoading HELCARAXE CNN model. This can take some time...\n"
        try:
            jTime, jShared, jStatus, jSession, jOpt = get_job(eID)

            if jStatus == JobStatus.error:
                cout = "Execution failed!"

            logPath = os.path.join(get_job_dir(eID), "auspex.log")
            if os.path.isfile(logPath):
                with open(logPath, "r") as logf:
                    tcout = logf.read()
                    if tcout:
                        cout = tcout
            # else:
            #    return abort(404)

        except IOError as e:
            pass
        except KeyError as e:
            pass
        except ValueError as e:
            return abort(404)

        return jsonify(cout=cout, status=jStatus, options=jOpt, time=jTime)
    return abort(404)  # render_generic_error(id=id, error="ID not found.")


# AJAX/JS
@app.route("/ajax_js/<id>")
def ajax_js(id):
    """Return AJAX.js modified with given jobID."""
    eID = enforce_b64(id)
    return render_template("ajax.js", id=eID)


# IMAGE ACCESS
@app.route("/amplitudes/<id>")
def amplitudes(id):
    """Return job amplitudes.png if it exists and session has access."""
    eID = enforce_b64(id)
    sessIdent = get_session_ident(enforceExisting=True)
    if eID and is_job_accessible(eID, sessIdent):
        fileID = os.path.join(get_job_dir(eID), "amplitudes.png")
        if os.path.exists(fileID):
            return send_file(fileID, attachment_filename="amplitudes.png")
    return abort(404)  # render_generic_error(id=id, error="ID not found.")


@app.route("/intensities/<id>")
def intensities(id):
    """Return job intensities.png if it exists and session has access."""
    eID = enforce_b64(id)
    sessIdent = get_session_ident(enforceExisting=True)
    if eID and is_job_accessible(eID, sessIdent):
        fileID = os.path.join(get_job_dir(eID), "intensities.png")
        if os.path.exists(fileID):
            return send_file(fileID, attachment_filename="intensities.png")
    return abort(404)  # render_generic_error(id=id, error="ID not found.")


@app.route("/identicon/<id>")
def identicon(id):
    """Return job identicon (hash.png) if it exists and session has access."""
    eID = enforce_b64(id)
    sessIdent = get_session_ident(enforceExisting=True)
    if eID and is_job_accessible(eID, sessIdent):
        fileID = os.path.join(get_job_dir(eID), "hash.png")
        if os.path.exists(fileID):
            return send_file(fileID, attachment_filename="hash.png")
    return abort(404)  # render_generic_error(id=id, error="ID not found.")


# RESULTS
@app.route("/results/<id>")
def results(id):
    """Results HTML page. Renders results.html with given job metadata (id, name, options) if session has access."""
    eID = enforce_b64(id)
    sessIdent = get_session_ident(enforceExisting=True)
    if eID and is_job_accessible(eID, sessIdent) and os.path.exists(get_job_dir(eID)):
        # get job options and extract data
        jShared, jOptions, jName = get_job(eID, keys=("shared", "options", "name"))
        optDict = {"ylim": "minmax", "ice": True, "dmin": "", "shared": jShared == 1}
        jOptList = jOptions.split(" ")
        # print(jOptList)
        while jOptList:
            key = jOptList.pop(0)
            if key == "--ylim":
                optVal = jOptList.pop(0)
                if optVal in ["minmax", "auto", "auto_low", "low"]:
                    optDict["ylim"] = optVal

            elif key == "--dmin":
                optVal = float(jOptList.pop(0))
                if optVal >= 0 or optVal <= 200:
                    optDict["dmin"] = optVal

            elif key == "--no-automatic":
                optDict["ice"] = False
        # print(optDict)

        return render_template("results.html", id=eID, name=jName, **optDict)
    return render_generic_error(id_=id, error="ID not found.")


# JOBLIST
@app.route("/joblist/")
def joblist():
    """Job list page. List all currently stored jobs for the given session. Renders joblist.html with given list of attributes."""
    sessIdent = get_session_ident(enforceExisting=True)
    jobList = []
    jobIDs = get_session_jobs(sessIdent)
    if jobIDs:
        for jID in jobIDs:
            if is_job_accessible(jID, sessIdent):  # FIXME: technically unnecessary
                startTime, jShared, jStatus, jOpt, jName = get_job(
                    jID, keys=("timestamp", "shared", "status", "options", "name")
                )
                stopTime = startTime + app.config["JOB_LIFETIME"]
                dateStr = str(datetime.datetime.utcfromtimestamp(startTime))
                exprStr = str(datetime.datetime.utcfromtimestamp(stopTime))
                try:
                    statStr = JobStatus(jStatus).name
                except (ValueError, AttributeError):
                    statStr = "Error"

                shrStr = "Shared" if jShared == 1 else "Private"
                jobList.append(
                    (jID, dateStr, exprStr, statStr, shrStr, startTime, stopTime, jName or "")
                )
    jobList = sorted(jobList, key=lambda x: x[1])
    return render_template("joblist.html", jobList=jobList)


# ERROR: NOT ENOUGH RESOURCES
@app.route("/error/resources")
def error_resources():
    """Error: Not enough resources. Redirected to if hard drive storage limit is reached and new job creation is attempted."""
    return render_template("error-resources.html")


# ERROR: TOO MANY ACTIVE JOBS
@app.route("/error/outofjobs")
def error_outofjobs():
    """Error: Out of jobs. Redirected to if per-session job limit is reached and new job creation is attempted."""
    return render_template("error-outofjobs.html", limit=app.config["JOBS_PER_SESSION"])


########################################
# ----- MAIN ------------------------- #
########################################

# start a locally accessible server on port 5000 for debugging if run directly.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
