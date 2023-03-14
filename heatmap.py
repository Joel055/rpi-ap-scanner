import numpy as np
import matplotlib.pyplot as plt
import matplotlib.colors as color
from scipy.interpolate import griddata


def generate(): #tar ej emot data just nu utan använder hardcodad data från tidigare mätning
    
    x = [154,63,161,131,247,196,250,200,261,207,271,211,271,216,272,217,276,223,276,227,245,246,242,240,231,199,278]
    y = [732 - num for num in [573,511,461,510,551,518,495,455,440,411,392,355,336,291,269,236,204,179,147,106,205,265,316,394,460,576,106]]
    signal_strength = [-62, -60, -57, -55, -42, -44, -52, -54, -53, -57, -58, -67, -65, -59, -58, -67, -58, -59, -59, -65, -55, -62, -63, -61, -55, -48, -64]

    # skapa och ändra storlek på grid
    xi = np.linspace(min(x), max(x), 1000)
    yi = np.linspace(min(y), max(y), 1000)

    #sparar minne, pga de nu oanvända variablerna kommer peka på samma minnesarea.
    xi, yi = np.meshgrid(xi, yi)

    #interpolering
    zi = griddata((x, y), signal_strength, (xi,yi), method='cubic')

    #färggränser
    bounds = [-75, -70, -60, -55, -50, -45, -40]
    cmap = color.ListedColormap([
        (255/255, 0/255, 0/255), # röd
        (255/255, 127/255, 0/255), # orange
        (255/255, 255/255, 0/255), # gul
        (128/255, 255/255, 0/255), 
        (0/255, 255/255, 0/255), #grön
        (0/255, 127/255, 0/255),
        (0/255, 63/255, 0/255) # mörk grön
    ])

    norm = plt.Normalize(min(bounds), max(bounds))
    colors = cmap(norm(zi))
    levels = [norm(b) for b in bounds]

    plt.imshow(colors, origin='lower', extent=[min(x), max(x), min(y), max(y)], aspect='auto')
    plt.colorbar()
    plt.xlabel('X')
    plt.ylabel('Y')
    plt.title('Signal Strength Heatmap')

    plt.scatter(x, y, s=20, c='white', edgecolors='black')

    x_range = max(x) - min(x)
    y_range = max(y) - min(y)
    x_pad = 0.1 * x_range
    y_pad = 0.1 * y_range
    plt.xlim([min(x) - x_pad, max(x) + x_pad])
    plt.ylim([min(y) - y_pad, max(y) + y_pad])

    plt.contour(xi, yi, zi, levels=levels, colors='white', linewidths=0.5) 

    plt.show()#funkar bara på windows, och kanske på linux med GUI


#colorbar behöver köras separat, har inte lyckats integrerar den i värmekartan
# bounds = [-80, -75, -65, -60, -53, -47, -40, -35]
# norm = colors.BoundaryNorm(bounds, cmap.N)

# fig, ax = plt.subplots(figsize=(0.3, 5))
# cb = plt.colorbar(plt.cm.ScalarMappable(cmap=cmap, norm=norm), cax=ax)
# cb.set_ticks(bounds)
# cb.ax.set_yticklabels(bounds)
# cb.ax.tick_params(labelright=True, labelleft=False)
# cb.ax.set_ylabel('(dBm)')

# plt.show()