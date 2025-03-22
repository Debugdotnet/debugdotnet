<h1 align="center">Hi 👋, I'm Debug</h1>

###

<h2 align="center">DevOps | InfoSec | Reversing | Forensics</h2>

###

<div align="center">
  <img height="200" src="https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExZTNpb2k1ZXQ0dzY5a2MycG1lZWc3NmkyMnp6aDIzY29nYWN2M29vZSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9cw/KFP1yGEGZ7smVitLhJ/giphy.gif"  />
</div>

###
class Profile:
    """
    A representation of my professional profile, highlighting areas of expertise,
    and technical skills.
    """

    def __init__(self):
        self.expertise = [
            "Living-off-the-land methodologies",
            "Covert infrastructure staging",
            "Ring-0 rootkit analysis and mitigation",
            "Infrastructure attribution through passive DNS and metadata analysis",
            "Digital artifact correlation and timeline reconstruction",
            "Analysis of non-standard network protocols",
            "Adversary emulation and TTP mapping",
            "Exploitation of memory safety vulnerabilities",
            "UEFI and firmware security assessment",
        ]
        self.tech_stack = {
            "Languages": ["C", "Python", "x86/x64 Assembly", "Go", "Shell"],
            "Web": ["Deep understanding of web application attack vectors", "Browser extension security analysis"],
            "Databases": ["Data exfiltration forensics", "Analysis of database-centric malware"],
            "Applications": ["IDA Pro", "Ghidra", "WinDbg", "Network protocol dissection tools", "Memory analysis platforms"],
            "Mathematics_and_Statistics": ["Applied cryptography principles", "Statistical methods for anomaly detection"],
            "Machine_Learning": ["Behavioral malware detection concepts"],
            "Toolchains": ["Custom scripting for analysis automation", "Orchestration of dynamic analysis environments", "Signature development for threat intelligence"],
            "DevOps": ["Secure infrastructure deployment for research"],
            "CloudOps": ["Cloud security architecture and threat landscape"],
            "Operating_Systems": ["Windows internals", "Linux kernel analysis", "embedded system architectures"],
            "IoT": ["Firmware security analysis"],
            "Architectures": ["x86/x64", "ARM"],
            "Mobile": ["Mobile platform security", "Mobile malware analysis"],
            "Editors": ["vim", "emacs"],
        }

    def display_profile(self):
        print("## 🕵️ Profile\n")

        self._display_expertise()
        self._display_tech_stack()

    def _display_expertise(self):
        print("### 💻 Expertise\n")
        print("```bash")
        print("$ cat expertise.txt\n")
        for item in self.expertise:
            print(f"* {item}")
        print("```\n")
    
    def _display_tech_stack(self):
        print("### 🛠️ Technologies\n")
        for category, items in self.tech_stack.items():
            print(f"<details><summary>{category}</summary>")
            for item in items:
                print(f"- {item}")
            print("</details>\n")
            

if __name__ == "__main__":
    my_profile = Profile()
    my_profile.display_profile()

###
