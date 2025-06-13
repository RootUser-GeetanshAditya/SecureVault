#!/usr/bin/env python3

import os
import json
import datetime

def get_directory_structure(path):
    """Get the complete structure of a directory recursively"""
    structure = {}
    
    try:
        items = os.listdir(path)
        items.sort()  # Sort alphabetically
        
        for item in items:
            item_path = os.path.join(path, item)
            
            # Skip hidden files and directories
            if item.startswith('.'):
                continue

            if item == 'index.html':
                continue
            
            if os.path.isdir(item_path):
                structure[item] = {
                    'type': 'folder',
                    'modified': get_modification_time(item_path),
                    'children': get_directory_structure(item_path)  # Recursively get subdirectories
                }
            elif item.endswith('.html') or item.endswith('.txt'):
                structure[item] = {
                    'type': 'file',
                    'size': os.path.getsize(item_path),
                    'modified': get_modification_time(item_path)
                }
            
            
            # Ignore non-HTML files for the blog system
            
    except PermissionError:
        pass  # Skip directories we can't read
        
    return structure

def get_modification_time(path):
    """Get formatted modification time"""
    try:
        timestamp = os.path.getmtime(path)
        return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')
    except:
        return 'Unknown'

def generate_static_index(blog_directory):
    """Generate a static index.html with embedded blog structure"""
    
    # Get the complete directory structure
    structure = get_directory_structure(blog_directory)
    structure_json = json.dumps(structure, indent=2)
    print(structure_json)
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureVault - Blog Management System</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {{
            --primary-bg: #0a0e1a;
            --secondary-bg: #1a1f35;
            --accent-bg: #242b42;
            --primary-color: #00d4ff;
            --secondary-color: #0099cc;
            --accent-color: #66ffcc;
            --warning-color: #ff6b35;
            --danger-color: #ff3366;
            --text-primary: #e6f3ff;
            --text-secondary: #b3d9ff;
            --text-muted: #8099b3;
            --border-color: #2d3748;
            --glow-color: rgba(0, 212, 255, 0.3);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            background: linear-gradient(135deg, var(--primary-bg) 0%, var(--secondary-bg) 50%, #0f1419 100%);
            color: var(--text-primary);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }}

        /* Animated background particles */
        .particles {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            pointer-events: none;
        }}

        .particle {{
            position: absolute;
            width: 2px;
            height: 2px;
            background: var(--primary-color);
            border-radius: 50%;
            opacity: 0.7;
            animation: float 8s infinite linear;
        }}

        @keyframes float {{
            from {{
                transform: translateY(100vh) rotate(0deg);
                opacity: 0;
            }}
            10% {{
                opacity: 0.7;
            }}
            90% {{
                opacity: 0.7;
            }}
            to {{
                transform: translateY(-100px) rotate(360deg);
                opacity: 0;
            }}
        }}

        /* Header */
        .header {{
            background: rgba(26, 31, 53, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border-color);
            padding: 1rem 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }}

        .header-content {{
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .logo {{
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary-color);
        }}

        .logo i {{
            font-size: 2rem;
            color: var(--accent-color);
            text-shadow: 0 0 10px var(--glow-color);
        }}

        .system-info {{
            display: flex;
            align-items: center;
            gap: 20px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}

        .status-indicator {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-color);
            animation: pulse 2s infinite;
        }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.3; }}
        }}

        /* Navigation breadcrumb */
        .breadcrumb {{
            background: rgba(36, 43, 66, 0.8);
            padding: 1rem 2rem;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.95rem;
        }}

        .breadcrumb-content {{
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .breadcrumb-item {{
            color: var(--text-secondary);
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 4px;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 4px;
        }}

        .breadcrumb-item:hover {{
            color: var(--primary-color);
            background: rgba(0, 212, 255, 0.1);
        }}

        .breadcrumb-separator {{
            color: var(--text-muted);
            font-size: 0.8rem;
        }}

        /* Main container */
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}

        /* Controls */
        .controls {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}

        .back-button {{
            background: linear-gradient(135deg, var(--danger-color), #cc2952);
            border: none;
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-family: inherit;
            font-size: 0.95rem;
            font-weight: 600;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 4px 15px rgba(255, 51, 102, 0.3);
        }}

        .back-button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(255, 51, 102, 0.4);
        }}

        .view-toggle {{
            display: flex;
            background: var(--accent-bg);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}

        .view-btn {{
            background: none;
            border: none;
            color: var(--text-secondary);
            padding: 10px 16px;
            cursor: pointer;
            transition: all 0.3s ease;
        }}

        .view-btn.active {{
            background: var(--primary-color);
            color: var(--primary-bg);
        }}

        /* File grid */
        .file-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1.5rem;
            margin-top: 1rem;
        }}

        .file-grid.list-view {{
            grid-template-columns: 1fr;
        }}

        .file-item {{
            background: linear-gradient(135deg, var(--secondary-bg), var(--accent-bg));
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            cursor: pointer;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}

        .file-item::before {{
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 212, 255, 0.1), transparent);
            transition: left 0.6s;
        }}

        .file-item:hover::before {{
            left: 100%;
        }}

        .file-item:hover {{
            transform: translateY(-4px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            border-color: var(--primary-color);
        }}

        .folder {{
            border-left: 4px solid var(--secondary-color);
        }}

        .folder:hover {{
            border-left-color: var(--primary-color);
            box-shadow: 0 10px 30px rgba(0, 153, 204, 0.2);
        }}

        .html-file {{
            border-left: 4px solid var(--warning-color);
        }}

        .html-file:hover {{
            border-left-color: var(--warning-color);
            box-shadow: 0 10px 30px rgba(255, 107, 53, 0.2);
        }}

        .file-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }}

        .file-icon {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}

        .folder .file-icon {{
            color: var(--secondary-color);
        }}

        .html-file .file-icon {{
            color: var(--warning-color);
        }}

        .file-type {{
            background: rgba(0, 212, 255, 0.1);
            color: var(--primary-color);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .folder .file-type {{
            background: rgba(0, 153, 204, 0.1);
            color: var(--secondary-color);
        }}

        .html-file .file-type {{
            background: rgba(255, 107, 53, 0.1);
            color: var(--warning-color);
        }}

        .file-name {{
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
            word-break: break-word;
        }}

        .file-meta {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 1rem;
        }}

        .file-size {{
            background: rgba(102, 255, 204, 0.1);
            color: var(--accent-color);
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 500;
        }}

        /* Footer status bar */
        .status-bar {{
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(26, 31, 53, 0.95);
            backdrop-filter: blur(20px);
            color: var(--text-secondary);
            padding: 12px 24px;
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .status-left {{
            display: flex;
            align-items: center;
            gap: 20px;
        }}

        .status-right {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        /* Responsive design */
        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}
            
            .header-content {{
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }}
            
            .file-grid {{
                grid-template-columns: 1fr;
                gap: 1rem;
            }}
            
            .controls {{
                flex-direction: column;
                align-items: stretch;
            }}
            
            .status-bar {{
                flex-direction: column;
                gap: 8px;
                text-align: center;
            }}
        }}

        /* Smooth scrollbar */
        ::-webkit-scrollbar {{
            width: 8px;
        }}

        ::-webkit-scrollbar-track {{
            background: var(--primary-bg);
        }}

        ::-webkit-scrollbar-thumb {{
            background: var(--border-color);
            border-radius: 4px;
        }}

        ::-webkit-scrollbar-thumb:hover {{
            background: var(--primary-color);
        }}
    </style>
</head>
<body>
    <div class="particles" id="particles"></div>
    
    <div class="header">
        <div class="header-content">
            <div class="logo">
                <i class="fas fa-shield-halved"></i>
                <span>SecureVault</span>
            </div>
            <div class="system-info">
                <div class="status-indicator">
                    <div class="status-dot"></div>
                    <span>STATIC</span>
                </div>
                <div>
                    <i class="fas fa-file-code"></i>
                    <span>Static HTML</span>
                </div>
                <div>
                    <i class="fas fa-lock"></i>
                    <span>Secure</span>
                </div>
            </div>
        </div>
    </div>

    <div class="breadcrumb">
        <div class="breadcrumb-content" id="breadcrumb">
            <div class="breadcrumb-item" onclick="navigateToPath('')">
                <i class="fas fa-home"></i>
                <span>Root Directory</span>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="controls">
            <button class="back-button" id="backButton" onclick="goBack()" style="display: none;">
                <i class="fas fa-arrow-left"></i>
                <span>Back</span>
            </button>
            
            <div class="view-toggle">
                <button class="view-btn active" onclick="setViewMode('grid')">
                    <i class="fas fa-th"></i>
                </button>
                <button class="view-btn" onclick="setViewMode('list')">
                    <i class="fas fa-list"></i>
                </button>
            </div>
        </div>
        
        <div class="file-grid" id="fileGrid"></div>
    </div>

    <div class="status-bar">
        <div class="status-left">
            <span><i class="fas fa-terminal"></i> SecureVault v3.0 Static</span>
            <span><i class="fas fa-shield-alt"></i> Offline Ready</span>
            <span><i class="fas fa-database"></i> Blog Archive</span>
        </div>
        <div class="status-right">
            <span id="currentTime"></span>
            <span><i class="fas fa-check-circle"></i> Generated</span>
        </div>
    </div>

    <script>
        // Embedded blog structure data
        const BLOG_STRUCTURE = {structure_json};
        
        let currentPath = '';
        let pathHistory = [''];
        let viewMode = 'grid';

        // Initialize particles animation
        function initParticles() {{
            const particlesContainer = document.getElementById('particles');
            const particleCount = 50;
            
            for (let i = 0; i < particleCount; i++) {{
                const particle = document.createElement('div');
                particle.className = 'particle';
                particle.style.left = Math.random() * 100 + '%';
                particle.style.animationDelay = Math.random() * 8 + 's';
                particle.style.animationDuration = (Math.random() * 3 + 5) + 's';
                particlesContainer.appendChild(particle);
            }}
        }}

        // Update current time
        function updateTime() {{
            const now = new Date();
            const timeString = now.toLocaleTimeString('en-US', {{ 
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            }});
            document.getElementById('currentTime').textContent = timeString;
        }}

        function getDirectoryStructure(path) {{
            if (!path) {{
                return BLOG_STRUCTURE;
            }}
            
            const pathParts = path.split('/').filter(p => p);
            let current = BLOG_STRUCTURE;
            
            for (const part of pathParts) {{
                if (current[part] && current[part].type === 'folder' && current[part].children) {{
                    current = current[part].children;
                }} else {{
                    return null; // Path not found
                }}
            }}
            
            return current;
        }}

        function renderFiles() {{
            const fileGrid = document.getElementById('fileGrid');
            const structure = getDirectoryStructure(currentPath);
            
            if (!structure) {{
                fileGrid.innerHTML = '<div class="error"><i class="fas fa-exclamation-triangle"></i>Directory not found</div>';
                return;
            }}
            
            fileGrid.innerHTML = '';
            
            Object.keys(structure).forEach(name => {{
                const item = structure[name];
                const fileItem = document.createElement('div');
                fileItem.className = `file-item ${{item.type === 'folder' ? 'folder' : 'html-file'}}`;
                
                const icon = item.type === 'folder' ? 'fas fa-folder' : 'fas fa-file-code';
                const typeText = item.type === 'folder' ? 'Directory' : 'Document';
                const sizeText = item.size ? formatFileSize(item.size) : '';
                
                fileItem.innerHTML = `
                    <div class="file-header">
                        <div class="file-icon">
                            <i class="${{icon}}"></i>
                        </div>
                        <div class="file-type">${{typeText}}</div>
                    </div>
                    <div class="file-name">${{name}}</div>
                    <div class="file-meta">
                        <span><i class="fas fa-clock"></i> ${{item.modified || 'Unknown'}}</span>
                        ${{sizeText ? `<span class="file-size">${{sizeText}}</span>` : ''}}
                    </div>
                `;
                
                fileItem.onclick = () => {{
                    if (item.type === 'folder') {{
                        navigateToFolder(name);
                    }} else {{
                        openFile(name);
                    }}
                }};
                
                fileGrid.appendChild(fileItem);
            }});
        }}

        function formatFileSize(bytes) {{
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + ' KB';
            return Math.round(bytes / (1024 * 1024)) + ' MB';
        }}

        function navigateToFolder(folderName) {{
            pathHistory.push(currentPath);
            currentPath = currentPath ? `${{currentPath}}/${{folderName}}` : folderName;
            updateBreadcrumb();
            renderFiles();
            
            const backButton = document.getElementById('backButton');
            backButton.style.display = currentPath ? 'block' : 'none';
        }}

        function navigateToPath(path) {{
            pathHistory.push(currentPath);
            currentPath = path;
            updateBreadcrumb();
            renderFiles();
            
            const backButton = document.getElementById('backButton');
            backButton.style.display = currentPath ? 'block' : 'none';
        }}

        function goBack() {{
            if (pathHistory.length > 1) {{
                pathHistory.pop();
                currentPath = pathHistory[pathHistory.length - 1];
                updateBreadcrumb();
                renderFiles();
                
                const backButton = document.getElementById('backButton');
                backButton.style.display = currentPath ? 'block' : 'none';
            }}
        }}

        function updateBreadcrumb() {{
            const breadcrumb = document.getElementById('breadcrumb');
            const pathParts = currentPath.split('/').filter(p => p);
            
            let breadcrumbHTML = `
                <div class="breadcrumb-item" onclick="navigateToPath('')">
                    <i class="fas fa-home"></i>
                    <span>Root Directory</span>
                </div>
            `;
            
            let buildPath = '';
            pathParts.forEach((part, index) => {{
                buildPath += (buildPath ? '/' : '') + part;
                breadcrumbHTML += `
                    <i class="fas fa-chevron-right breadcrumb-separator"></i>
                    <div class="breadcrumb-item" onclick="navigateToPath('${{buildPath}}')">
                        <i class="fas fa-folder"></i>
                        <span>${{part}}</span>
                    </div>
                `;
            }});
            
            breadcrumb.innerHTML = breadcrumbHTML;
        }}

        function setViewMode(mode) {{
            viewMode = mode;
            const fileGrid = document.getElementById('fileGrid');
            const buttons = document.querySelectorAll('.view-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.closest('.view-btn').classList.add('active');
            
            if (mode === 'list') {{
                fileGrid.classList.add('list-view');
            }} else {{
                fileGrid.classList.remove('list-view');
            }}
        }}

        function openFile(fileName) {{
            const fullPath = currentPath ? `${{currentPath}}/${{fileName}}` : fileName;
            window.open(fullPath, '_blank');
        }}

        // Initialize the application
        window.onload = function() {{
            initParticles();
            renderFiles();
            updateTime();
            setInterval(updateTime, 1000);
        }};

        // Keyboard navigation
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape' && currentPath) {{
                goBack();
            }}
        }});
    </script>
</body>
</html>'''
    
    return html_content

def main():
    """Main function to generate the static blog index"""
    blog_directory = os.path.join(os.getcwd(), '.')
    
    if not os.path.exists(blog_directory):
        print(f"Error: Blog directory '{blog_directory}' does not exist!")
        print("Please create the 'blog_storage' directory and add your HTML files.")
        return
    
    print("Scanning blog directory structure...")
    print(f"Blog directory: {blog_directory}")
    
    # Generate the static HTML content
    html_content = generate_static_index(blog_directory)
    
    # Write the index.html file to the blog_storage directory
    index_path = os.path.join(".",'index.html')
    
    try:
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ Static index.html generated successfully!")
        print(f"📁 Location: {index_path}")
        print(f"🌐 Open {index_path} in your browser to view your blog")
        
        # Count files and folders for summary
        def count_items(structure):
            files = 0
            folders = 0
            for item in structure.values():
                if item['type'] == 'folder':
                    folders += 1
                    if 'children' in item:
                        sub_files, sub_folders = count_items(item['children'])
                        files += sub_files
                        folders += sub_folders
                else:
                    files += 1
            return files, folders
        
        structure = get_directory_structure(blog_directory)
        total_files, total_folders = count_items(structure)
        
        print(f"📊 Summary: {total_files} HTML files, {total_folders} folders indexed")
        
    except Exception as e:
        print(f"❌ Error writing index.html: {str(e)}")

if __name__ == '__main__':
    main()
