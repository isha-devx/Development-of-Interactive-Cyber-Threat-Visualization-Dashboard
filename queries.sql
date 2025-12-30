-- SQL Task: Analyzing Cyber Threat Data

-- 1. Count of incidents per Attack Type
SELECT Attack_Type, COUNT(*) as Total_Incidents
FROM cyber_threats
GROUP BY Attack_Type
ORDER BY Total_Incidents DESC;

-- 2. Identify High and Critical Severity Threats
SELECT Incident_ID, Source_IP, Attack_Type, Severity
FROM cyber_threats
WHERE Severity IN ('High', 'Critical');

-- 3. Top 3 Countries by Number of Attacks
SELECT Country, COUNT(*) as Incident_Count
FROM cyber_threats
GROUP BY Country
ORDER BY Incident_Count DESC
LIMIT 3;

-- 4. Calculate Average Traffic Volume by Protocol
SELECT Protocol, AVG(Traffic_Volume_MB) as Avg_Traffic
FROM cyber_threats
GROUP BY Protocol;
