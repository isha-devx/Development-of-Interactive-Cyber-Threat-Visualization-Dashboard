import dash
from dash import dcc, html
import plotly.express as px
import pandas as pd

# 1. Load the data you shared
df = pd.read_csv('cyber_threat_data.csv')

# 2. Initialize the Dash app
app = dash.Dash(__name__)

# 3. Create Map (Outcome 1)
fig_map = px.scatter_geo(df, locations="Country", locationmode='country names', 
                         color="Severity", size_max=15,
                         title="Global Cyber Threat Distribution")

# 4. Create Attack Type Chart (Outcome 3)
fig_bar = px.bar(df, x='Attack_Type', color='Severity', title="Attack Frequency by Type")

# 5. Dashboard Layout
app.layout = html.Div(style={'backgroundColor': '#111', 'color': 'white', 'padding': '20px'}, children=[
    html.H1("Cyber Threat Visualization Dashboard - Group 1", style={'textAlign': 'center'}),
    dcc.Graph(figure=fig_map),
    dcc.Graph(figure=fig_bar)
])

if __name__ == '__main__':
    app.run_server(debug=True)
