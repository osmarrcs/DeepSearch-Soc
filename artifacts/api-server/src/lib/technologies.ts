export interface Technology {
  id: string;
  name: string;
  category: string;
}

export const TECHNOLOGIES: Technology[] = [
  // Infraestrutura
  { id: "fortigate", name: "Fortigate", category: "Infraestrutura" },
  { id: "fortinet-manager", name: "Fortinet Manager", category: "Infraestrutura" },
  { id: "fortinet-analyser", name: "Fortinet Analyser", category: "Infraestrutura" },
  { id: "fortinet-ems", name: "Fortinet EMS", category: "Infraestrutura" },
  { id: "cisco-antispam", name: "Cisco Antispam", category: "Infraestrutura" },
  { id: "senha-segura-pam", name: "Senha Segura PAM", category: "Infraestrutura" },
  { id: "f5-bigip-waf", name: "F5 Big IP WAF", category: "Infraestrutura" },
  { id: "aws", name: "AWS", category: "Infraestrutura" },
  { id: "openshift", name: "Openshift", category: "Infraestrutura" },
  { id: "microsoft", name: "Microsoft", category: "Infraestrutura" },
  { id: "vmware", name: "VMware", category: "Infraestrutura" },
  { id: "network-devices", name: "Network Devices", category: "Infraestrutura" },
  { id: "operating-systems", name: "Operating Systems", category: "Infraestrutura" },
  { id: "cloud-platforms", name: "Cloud Platforms", category: "Infraestrutura" },
  { id: "virtualization-software", name: "Virtualization Software", category: "Infraestrutura" },

  // Sistemas de Produção
  { id: "git", name: "Git", category: "Sistemas de Produção" },
  { id: "ansible", name: "Ansible", category: "Sistemas de Produção" },
  { id: "kubernetes", name: "Kubernetes", category: "Sistemas de Produção" },
  { id: "cicd-tools", name: "CI/CD Tools", category: "Sistemas de Produção" },
  { id: "containers", name: "Containers", category: "Sistemas de Produção" },
  { id: "orchestration-platforms", name: "Orchestration Platforms", category: "Sistemas de Produção" },

  // Banco de Dados
  { id: "oracle", name: "Oracle", category: "Banco de Dados" },
  { id: "postgresql", name: "PostgreSQL", category: "Banco de Dados" },
  { id: "mysql", name: "MySQL", category: "Banco de Dados" },
  { id: "sql-server", name: "SQL Server", category: "Banco de Dados" },
  { id: "mongodb", name: "MongoDB", category: "Banco de Dados" },
  { id: "redis", name: "Redis", category: "Banco de Dados" },

  // Navegadores
  { id: "google-chrome", name: "Google Chrome", category: "Navegadores" },
  { id: "mozilla-firefox", name: "Mozilla Firefox", category: "Navegadores" },
  { id: "microsoft-edge", name: "Microsoft Edge", category: "Navegadores" },
  { id: "safari", name: "Safari", category: "Navegadores" },
  { id: "brave", name: "Brave", category: "Navegadores" },
  { id: "opera", name: "Opera", category: "Navegadores" },

  // Aplicações / Desenvolvimento
  { id: "winzip", name: "WinZip", category: "Aplicações / Desenvolvimento" },
  { id: "7zip", name: "7-Zip", category: "Aplicações / Desenvolvimento" },
  { id: "obs-studio", name: "OBS Studio", category: "Aplicações / Desenvolvimento" },
  { id: "docker", name: "Docker", category: "Aplicações / Desenvolvimento" },
  { id: "vscode", name: "Visual Studio Code", category: "Aplicações / Desenvolvimento" },
  { id: "jetbrains", name: "JetBrains IDEs", category: "Aplicações / Desenvolvimento" },
  { id: "npm", name: "npm", category: "Aplicações / Desenvolvimento" },
  { id: "python", name: "Python Packages", category: "Aplicações / Desenvolvimento" },
  { id: "dev-tools", name: "Development Tools", category: "Aplicações / Desenvolvimento" },
  { id: "productivity-software", name: "Productivity Software", category: "Aplicações / Desenvolvimento" },
  { id: "file-archivers", name: "File Archivers", category: "Aplicações / Desenvolvimento" },
  { id: "streaming-software", name: "Streaming Software", category: "Aplicações / Desenvolvimento" },
];
