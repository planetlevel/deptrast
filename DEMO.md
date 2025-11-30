# SBOM Visualization Demo

## Quick Demo

The visualization tool creates an interactive dependency tree similar to the gif you provided, with these features:

### Visual Design
- **Dark theme** with syntax highlighting
- **Color-coded components**:
  - 🟢 Group names (teal): `org.springframework.boot`
  - 🟡 Artifact names (yellow): `spring-boot-starter-web`
  - ⚪ Versions (gray): `@1.5.4.RELEASE`

### Interactive Features
- **Click to expand/collapse** - Click the ▶/▼ arrows to show/hide dependencies
- **Search** - Real-time filtering as you type
- **Expand/Collapse All** - Bulk operations for the entire tree
- **Statistics Dashboard** - Shows:
  - Total components count
  - Number of direct dependencies
  - Maximum dependency depth
  - SBOM format and version

### Example Tree Structure

```
▼ org.springframework.boot/spring-boot-starter-web@1.5.4.RELEASE
  ▼ com.fasterxml.jackson.core/jackson-databind@2.8.8
    • com.fasterxml.jackson.core/jackson-annotations@2.8.0
    • com.fasterxml.jackson.core/jackson-core@2.8.8
  ▼ org.hibernate/hibernate-validator@5.3.5.Final
    • com.fasterxml/classmate@1.3.3
    • javax.validation/validation-api@1.1.0.Final
    • org.jboss.logging/jboss-logging@3.3.1.Final
  ▼ org.springframework.boot/spring-boot-starter@1.5.4.RELEASE
    ▼ org.springframework.boot/spring-boot@1.5.4.RELEASE
      • org.springframework/spring-context@4.3.9.RELEASE
      • org.springframework/spring-core@4.3.9.RELEASE
```

## Try It Now

### Option 1: Standalone HTML File
```bash
# Open the standalone version
open sbom-viz.html

# Then load: src/test/resources/petclinic-deptrast-from-maven.sbom
```

### Option 2: Python Script
```bash
# Automatically opens browser with embedded SBOM data
python3 python/deptrast/commands/graph.py src/test/resources/petclinic-deptrast-from-maven.sbom
```

### Option 3: Convenience Script
```bash
# One-liner
./scripts/visualize-sbom.sh src/test/resources/petclinic-deptrast-from-maven.sbom
```

## What You'll See

### Statistics Panel (Top)
```
┌─────────────────────────────────────────────────────────────┐
│ Total Components: 103                                       │
│ Direct Dependencies: 15                                     │
│ Max Depth: 6                                                │
│ SBOM Format: CycloneDX 1.6                                 │
└─────────────────────────────────────────────────────────────┘
```

### Dependency Tree (Main View)

The tree shows all 103 components from the Petclinic SBOM:
- Spring Boot starters and frameworks
- Hibernate ORM and JPA
- Selenium testing libraries
- Tomcat embedded server
- Jackson JSON processing
- And all their transitive dependencies

### Interaction Examples

1. **Find a specific dependency**:
   - Type "jackson" in search box
   - All Jackson-related components highlight

2. **Explore Spring dependencies**:
   - Click ▼ next to `spring-boot-starter-web`
   - See all transitive dependencies
   - Click any sub-dependency to explore further

3. **Collapse unnecessary sections**:
   - Click "Collapse All"
   - Expand only the sections you care about
   - Get a clean view of your dependency structure

## Technical Details

- **Performance**: Handles 100+ components smoothly
- **Circular Dependency Detection**: Marks circular refs as "(circular)"
- **No Network Required**: Works completely offline
- **Shareable**: HTML files are self-contained and portable
- **Responsive**: Works on desktop and tablet screens

## Next Steps

After testing:
1. Review the interactive visualization
2. Try it with your own SBOM files
3. Decide if you want to integrate as `deptrast graph` command
4. See `INTEGRATION-PLAN.md` for implementation details
