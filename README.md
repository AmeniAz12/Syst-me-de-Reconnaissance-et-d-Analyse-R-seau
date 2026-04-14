# 🔐 Cyber Network Scanner

Un outil simplifié inspiré de Nmap à des fins éducatives, démontrant les concepts de scan réseau et les techniques de cybersécurité.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-Educational%20Only-red.svg)
![Status](https://img.shields.io/badge/status-Production%20Ready-green.svg)

## 🎯 Objectif

Créer un outil de scan réseau basé sur Python qui simule les outils professionnels d’évaluation de sécurité tout en restant éducatif et sécurisé. Ce projet démontre des concepts fondamentaux de cybersécurité tels que le scan de ports, la détection de services, le banner grabbing et la reconnaissance réseau.

## ⚠️ AVERTISSEMENT DE SÉCURITÉ

**IMPORTANT : Cet outil est destiné à un usage STRICTEMENT ÉDUCATIF.**

- ❌ **NE PAS** scanner des réseaux qui ne vous appartiennent pas  
- ❌ **NE PAS** scanner sans autorisation écrite explicite  
- ❌ **NE PAS** utiliser à des fins malveillantes  
- ✅ Scanner uniquement vos propres réseaux ou des environnements autorisés  

**Le scan réseau non autorisé est illégal et contraire à l’éthique.** Utilisez cet outil de manière responsable et conforme aux lois.

## 🚀 Fonctionnalités

### Capacités principales
- **Scan de ports** : scan TCP avec détection ouvert/fermé/filtré  
- **Multi-threading** : scan concurrent configurable pour améliorer les performances  
- **Détection de services** : identification automatique des services selon les ports  
- **Banner Grabbing** : récupération des informations de service et versions  
- **Découverte d’hôtes** : identification des machines actives sur le réseau  
- **Scan de sous-réseaux** : scan de réseaux CIDR (ex : 192.168.1.0/24)  

### Fonctionnalités avancées
- **Mode furtif** : délais configurables entre les scans  
- **Plages de ports flexibles** : ports uniques, plages ou ports communs  
- **Export des résultats** : JSON, TXT, CSV avec rapports détaillés  
- **Recommandations de sécurité** : analyse automatique des vulnérabilités  
- **Suivi de progression** : affichage en temps réel de l’avancement du scan  

## 📋 Prérequis

- Python 3.7 ou supérieur  
- Aucune dépendance externe (librairie standard Python uniquement)  
- Des privilèges administrateur peuvent être nécessaires pour certains scans  

## 🛠️ Installation

1. **Cloner le dépôt**
   ```bash
   git clone https://github.com/yourusername/network-scanner.git
   cd network-scanner
