# score_dev_env
A tool to automatically score the Development Environment Project. The project description is included here, for completeness, as well.

Run this tool from inside your Virtual Machine and it will tell you if you've met all the requirements of the project.

## Get it
The easiest way to get this tool into your VM is to run the commands:

```sh
git clone https://github.com/jbaldus/score_dev_env ~/score
```

## Prepare the tool
then move to the `~/score` directory with

```sh
cd ~/score
```

and install the Python dependencies with

```sh
python3 -m pip install -r requirements.txt
```

## Get your score
Anytime you want to get your score with a breakdown of the tasks you have done and which you still need to do, you can accomplish this by running:

```sh
sudo python3 ~/score/score.py
```

and you should be met with a screen that looks like this:

![Overview](https://github.com/jbaldus/score_dev_env/raw/main/imgs/overview.png)

# Caveats
As awesome as this little scoring script is, there are a few things to be aware of:

* Even though the Development Environment Project says students can install non-Debian-based distros, like Fedora or Manjaro, this scoring script will only fully work on Debian-based distributions. It has been tested most on Ubuntu.
* False Positives: It doesn't exactly check **everything**. For example, it only just checks to see if `updatedb` is in a script file in `/etc/cron.daily` or _anywhere_ in the `/etc/crontab` file.
* False Negatives: It might not correctly check some thing or another thing. It might not check _all_ the ways a requirement might be satisfied.
* Bonus Points: There are a couple of checks that will appear for a few bonus tasks. Technically speaking, achieving these bonus tasks would be a case of **NOT** satisfying the requirements of the project.

## I got an error setting this up
You might get an error if you run one of the previous commands, if it has not been installed. On Debian-based systems, you should be able to get everything you need with:

```sh
sudo apt install git python3-pip
```

If running that command gives you an error saying that `Package 'python3-pip' has no installation candidate`, then run 

```sh 
sudo apt update
```

and then retry the installation command.

### That didn't fix it
You might be running into an error that has been fixed since you originally downloaded the program. You can try updating the scoring program by running

```sh
git pull
```

in the directory where you downloaded this program. Then try whatever you were trying to do when you got an error.
