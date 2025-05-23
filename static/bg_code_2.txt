import pygame, time, random

# Define classes / functions
class Construct:
    """
    Class for generic object inside of game
    """
    def __init__(self,size,x=0,y=0):
        self.x = x
        self.y = y
        self.size=size
        self.rect=pygame.Rect(self.x,self.y,self.size[0],self.size[1])
        
    

class Entity(Construct):
    """
    Class for moving objects such as enemies and the player.
    """
    def __init__(self, size, x, y):
        super().__init__(size,x,y) # init attributes from parent class constructor
        self.bullets=[] 

    def render(self,screen):
        """
        renders the object with the sprite
        """
        self.imagesize = self.image.get_size()
        # pygame.draw.rect(screen, (255,255,255), self.rect) # old rect render
        screen.blit(pygame.transform.scale(self.image,(int(self.imagesize[0]/3), int(self.imagesize[1]/3))),self.rect)

    def move(self, vel_x : int, vel_y : int, vel_inverse : int): # movement method
        """
        vel_x and vel_y parameters are for the speed of movement in x and y axis
        vel_inverse should only accept 1 or -1 as a parameter, and states whether if the velocity should be reversed
        """
        self.x += vel_x*vel_inverse # vel_inverse changes the direction
        self.y += vel_y*vel_inverse # 
        self.rect=pygame.Rect(self.x,self.y,self.size[0],self.size[1]) #update rect attribute with new one when moved

    def getxy(self):
        """
        returns x and y coordinates in a tuple
        """
        return(self.x,self.y) #returns position as a tuple
    

#enemy class
class Enemy(Entity):
    def __init__(self, size, x=0, y=0):
        super().__init__(size, x, y) # init attributes from parent class constructor
        self.image = pygame.image.load(r"sources\sprites\enemy.png")
    def shoot(self):
        """
        Appends a new object of class Bullet into attribute bullets.
        """
        self.bullets.append(Bullet(self.x+(self.size[0]/2), self.y,1))
    

#player class
class Player(Entity):
    def __init__(self, size, x, y):
        self.image = pygame.image.load(r"sources\sprites\player.png")
        super().__init__(size, x, y)
    
    def shoot(self):
        """
        Appends a new object of class Bullet into attribute bullets.
        """
        self.bullets.append(Bullet(self.x+(self.size[0]/2), self.y, -1))
    
    def die(self):
        self.x=20
        self.y=200
        self.rect=pygame.Rect(self.x,self.y,self.size[0],self.size[1])
        pygame.mixer.Sound.play(sounds["player_death"])

class Bullet(Entity):
    def __init__(self, x, y, downwards):
        self.image = pygame.image.load(r"sources\sprites\shot.png")
        super().__init__([3,7],x-1.5,y)
        self.downwards=downwards


class Shield(Construct):
    def __init__(self, x, y):
        super().__init__([35,15],x,y)
        self.__damageBlocks=[]

    def __damage(self,x,y):
        """
        private method that appends Damage object to private attribute damageBlocks
        """
        self.__damageBlocks.append(Damage(x,y))
    
    #render method for shield 
    def render(self,screen):
        pygame.draw.rect(screen, (255,255,255), self.rect) 
        #renders the black damage rects over the shield
        for damage in self.__damageBlocks:
            pygame.draw.rect(screen, (0,0,0), damage.rect)
    
    def testBulletCollision(self, bullet, destructive):
        """
        Method that will return True if there is a bullet that collides with the shield.
        When it collides, it will create a Damage object at the place where the bullet hit.
        """
        damaged_area=False
        for damage in self.__damageBlocks:
            #checks for if the bullet is in any of the damaged areas in the shield
            if pygame.Rect.colliderect(damage.top_hitbox,bullet.rect):
                damaged_area=True
        #if the bullet is not in a damaged area, 
        if pygame.Rect.colliderect(self.rect,bullet.rect) and not damaged_area:
            #find the xy of the bullet
            xy=bullet.getxy()    # returns tuple
            if destructive:
                self.__damage(xy[0],xy[1]) # create damage at the x and y of the bullet
            return True # returns that it did collide
        

class Damage(Construct):
    def __init__(self,x,y):
        super().__init__([5,random.randint(7,9)], x, y)
        #creates attributes that shows what the top hitbox is for the rect (I couldnt figure out how to get it to test the top of the rect)
        self.top_hitbox=pygame.Rect(self.x,self.y,self.size[0],1)

    
#hastily put together text rendering
def message(text):
    return font.render(text, False, (255,255,255)) 

#pygame initialisation
pygame.init()
screen = pygame.display.set_mode([224,256])

clock = pygame.time.Clock()
running = True

#spritesheet init

#spawning enemies
enemyObjs=[]
for x in range(0,10):
    for y in range(0,5):
        enemyObjs.append(Enemy([10,5], x*15+20, y*10+25))


#spawning shields
shields=[]
for x in range(0,3):
    shields.append(Shield((screen.get_width())/3*x+20,165))
prev_time=time.time()
dt=0

player=Player( [20,7.5] , 20, 200)

#initialise event for moving Enemy
movement_clock=pygame.NUMEVENTS-1

#timer for moving enemy
time_elapsed=0

#timer for shooting
shoot_cooldown=0

#count for how many times the aliens hit the wall
count=0

# -1 = going lef t  1 = going right
vel_inverse=1

enemy_shoot_cd=500

lives=3

score=0

# SOUNDS

pygame.mixer.init()

sounds={"shoot" : pygame.mixer.Sound(r"sources\sounds\shoot.wav"),
        "invader_death" : pygame.mixer.Sound(r"sources\sounds\invaderkilled.wav"),
        "invader_move" : pygame.mixer.Sound(r"sources\sounds\invader1.wav"),
        "player_death" : pygame.mixer.Sound(r"sources\sounds\explosion.wav")}

#FONT/TEXT
pygame.font.init()
font=pygame.font.SysFont('arial',  30)


#main loop, running state
while running: 
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running == False
    
    screen.fill(0)
    # DO GAME LOGIC
    fps=pygame.time.Clock.get_fps(clock)
    now=time.time()
    dt=now-prev_time
    prev_time=now
    time_elapsed+=dt*1000 #dt in ms

    #player input
    keys=pygame.key.get_pressed()
    if keys[pygame.K_LEFT] and player.getxy()[0]>5:
        player.move(2, 0, -1)
    elif keys[pygame.K_RIGHT] and player.getxy()[0]<screen.get_width()-25:
        player.move(2 ,0, 1)
    if keys[pygame.K_SPACE]:
        #if user wants to shoot, check if cooldwon is over
        if now-shoot_cooldown>0.3: #figures out when the last bullet was shot versus the time now
            shoot_cooldown=now
            player.shoot()
            pygame.mixer.Sound.play(sounds["shoot"])

###
    if time_elapsed<enemy_shoot_cd+25 and time_elapsed>enemy_shoot_cd-25:
        #1-2 enemies shoot
        for x in range(0,random.randint(0,2)):
            #create bullet obj using shoot method
            enemyObjs[random.randint(0,len(enemyObjs)-1)].shoot()
        #randomizes shoot cooldown
        enemy_shoot_cd=random.randint(0,750)
###
    if time_elapsed>1000:
        #in ms
        #checks to move down    
        if enemyObjs[-1].getxy()[0]>screen.get_width()-30:
            vel_inverse=-1
            count+=1
        
        elif enemyObjs[0].getxy()[0]<30:
            vel_inverse=1
            count+=1
        #if it hits the wall 4 times, move down
        if count==4:
            for mob in enemyObjs:
                mob.move(0,15,1)
            count=0
        else:
            for mob in enemyObjs:
                mob.move(10,0,vel_inverse)
        time_elapsed=0


    for mob in enemyObjs:
        #mob bullet collisions
        for bullet in player.bullets:                                                                                                                              
            if pygame.Rect.colliderect(mob.rect,bullet.rect):
                #if collision of enemy and bullet, remove from list / kill:
                player.bullets.pop(player.bullets.index(bullet))
                enemyObjs.pop(enemyObjs.index(mob))
                pygame.mixer.Sound.play(sounds["invader_death"])
                score+=20

            #tests each shield to see if it would collide
            for shield in shields:
                if shield.testBulletCollision(bullet,False):
                    #remove bullet if it collides
                    player.bullets.pop(player.bullets.index(bullet))
        
        for bullet in mob.bullets:
            for shield in shields:
                if shield.testBulletCollision(bullet,True):
                    mob.bullets.pop(mob.bullets.index(bullet))


            if pygame.Rect.colliderect(bullet.rect,player.rect):
                lives-=1
                player.die()
                player.render(screen)
                mob.bullets.pop(mob.bullets.index(bullet))
        
    #render shields and it's damage
    for shield in shields:
        shield.render(screen)

    #move bullets for player & enemies
    for bullet in player.bullets:
        bullet.move(0,5,bullet.downwards)
        bullet.render(screen)
    for mob in enemyObjs:
        for bullet in mob.bullets:
            bullet.move(0,5,bullet.downwards)
            bullet.render(screen)
        mob.render(screen)
            
    player.render(screen)
    pygame.display.flip()
    clock.tick(60)

    #losing conditions: died 3 times or enemies get too close
    if lives<=0 or enemyObjs[-1].y>160:
        #lost game, stop running state
        running=False

#end state
endScreen=True


while endScreen:
    screen.fill(0)
    text = message('Your Score: '+str(score))
    screen.blit(text,(0,0))
    text = message('Press Esc to leave the game')
    screen.blit(text,(0,100))
    

    keys=pygame.key.get_pressed()
    if keys[pygame.K_ESCAPE]:
        endScreen=False
        pygame.quit()
    pygame.display.flip()
    clock.tick(60)
    
pygame.quit()
